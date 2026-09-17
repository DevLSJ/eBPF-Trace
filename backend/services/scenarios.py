"""Bounded synthetic feature rehearsals: no sockets, subprocesses or alert delivery."""
import asyncio
import copy
import logging
import time
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select, update

from backend.core.schemas import FlowMessage, Thresholds
from backend.db.crud import utc_iso
from backend.db.models import ScenarioRun, ScenarioSample, utcnow
from backend.services.detection import process_flow, traffic_message
from ml.rule_engine import RuleEngine

CATALOG = [
    {'id': 'intrusion', 'name': '침입 탐지 리허설', 'description': '정상 접속 → 포트 탐색 → SYN 폭주 → 대량 전송 → 회복',
     'stages': ['baseline', 'recon', 'flood', 'transfer', 'recovery']},
    {'id': 'syn_flood', 'name': 'SYN Flood', 'description': '출발지 SYN 증가와 연결 폭주 탐지 확인',
     'stages': ['baseline', 'flood', 'recovery']},
    {'id': 'port_scan', 'name': 'Port Scan', 'description': '다수 목적지 포트 접근과 탐색 이벤트 확인',
     'stages': ['baseline', 'recon', 'recovery']},
    {'id': 'large_flow', 'name': '대량 데이터 전송', 'description': '전송량 급증을 통한 LARGE FLOW 규칙 확인',
     'stages': ['baseline', 'transfer', 'recovery']},
]
EXPECTED = {'baseline': 'BENIGN', 'recovery': 'BENIGN', 'recon': 'PORT_SCAN',
            'flood': 'SYN_FLOOD', 'transfer': 'LARGE_FLOW'}
STEP_SECONDS = 1
SAMPLES_PER_STAGE = 3


def catalog():
    return [{**item, 'duration_seconds': len(item['stages']) * SAMPLES_PER_STAGE,
             'source': 'simulation'} for item in CATALOG]


def message_for(stage, step):
    features = dict(pkt_rate=35, byte_rate=28000, syn_ratio=0.03, port_entropy=0.2,
                    port_cnt=2, flow_duration=1000, avg_pkt_size=800,
                    source_pkt_rate=35, source_syn_rate=1)
    if stage == 'recon':
        features.update(pkt_rate=80, byte_rate=4800, syn_ratio=1, port_entropy=5.58,
                        port_cnt=48, source_pkt_rate=80, source_syn_rate=80, avg_pkt_size=60)
    elif stage == 'flood':
        features.update(pkt_rate=4200 + step * 20, byte_rate=260000, syn_ratio=0.98,
                        port_cnt=1, source_pkt_rate=4800, source_syn_rate=4700, avg_pkt_size=60)
    elif stage == 'transfer':
        features.update(pkt_rate=9500, byte_rate=13_500_000 + step * 1000,
                        avg_pkt_size=1422, source_pkt_rate=9500)
    return FlowMessage(type='flow_features', message_id=uuid4(), timestamp=int(time.time() * 1000),
                       flow=dict(src_ip='192.0.2.10', dst_ip='198.51.100.20',
                                 src_port=41000 + step, dst_port=443, protocol=6), features=features)


def run_dict(row):
    return {'id': row.id, 'scenario_id': row.scenario_id, 'status': row.status,
            'started_at': utc_iso(row.started_at),
            'finished_at': utc_iso(row.finished_at) if row.finished_at else None,
            'thresholds': row.thresholds, 'detection_mode': row.detection_mode,
            'source': 'simulation'}


async def run_detail(session, run_id):
    row = await session.get(ScenarioRun, run_id)
    if row is None:
        raise HTTPException(404, 'Scenario run not found')
    samples = list(await session.scalars(select(ScenarioSample).where(
        ScenarioSample.run_id == run_id).order_by(ScenarioSample.step)))
    items = [{'step': s.step, 'timestamp': utc_iso(s.timestamp), 'stage': s.stage,
              'expected_label': s.expected_label, 'detected_label': s.detected_label,
              'features': s.features, 'anomaly_score': s.anomaly_score, 'event_id': s.event_id}
             for s in samples]
    return {**run_dict(row), 'samples': items, 'event_count': sum(s.event_id is not None for s in samples),
            'matched_steps': sum(s.expected_label == s.detected_label for s in samples),
            'sample_count': len(samples)}


class ScenarioService:
    def __init__(self, app):
        self.app, self.lock, self.tasks = app, asyncio.Lock(), {}

    async def recover(self):
        async with self.app.state.db.sessions() as session:
            await session.execute(update(ScenarioRun).where(ScenarioRun.status == 'running').values(
                status='interrupted', finished_at=utcnow()))
            await session.commit()

    async def start(self, body):
        async with self.lock:
            async with self.app.state.db.sessions() as session:
                existing = await session.get(ScenarioRun, str(body.request_id))
                if existing:
                    if existing.scenario_id != body.scenario_id:
                        raise HTTPException(409, 'Request ID belongs to a different scenario')
                    return run_dict(existing)
                if self.tasks:
                    raise HTTPException(409, 'A scenario is already running; wait or stop it first')
                detector = copy.copy(self.app.state.detector)
                detector.rules = RuleEngine(Thresholds(**detector.rules.thresholds.model_dump()))
                if not self.app.state.redis_available:
                    detector.model = None
                row = ScenarioRun(id=str(body.request_id), scenario_id=body.scenario_id,
                                  status='running', thresholds=detector.rules.thresholds.model_dump(),
                                  detection_mode=detector.mode if self.app.state.redis_available else 'rules_only')
                session.add(row)
                await session.commit()
                await session.refresh(row)
                result = run_dict(row)
            task = asyncio.create_task(self.execute(row.id, row.scenario_id, detector))
            self.tasks[row.id] = task
            task.add_done_callback(lambda _: self.tasks.pop(row.id, None))
            return result

    async def execute(self, run_id, scenario_id, detector):
        status = 'completed'
        try:
            stages = next(s['stages'] for s in CATALOG if s['id'] == scenario_id)
            step = 0
            for stage in stages:
                for _ in range(SAMPLES_PER_STAGE):
                    message = message_for(stage, step)
                    async with self.app.state.db.sessions() as session:
                        result, event = await process_flow(self.app, session, message, detector=detector,
                            source='simulation', run_id=run_id, expected_label=EXPECTED[stage],
                            use_ml=detector.mode == 'hybrid')
                        session.add(ScenarioSample(run_id=run_id, step=step, stage=stage,
                            expected_label=EXPECTED[stage], detected_label=result['attack_type'] if result['severity'] else 'BENIGN',
                            features=message.features.model_dump(), anomaly_score=result['anomaly_score'],
                            event_id=event['event_id'] if event else None))
                        await session.commit()  # Event + graph sample are one transaction.
                    if event:
                        await self.app.state.manager.broadcast(event)
                    await self.app.state.manager.broadcast(traffic_message(message, result, source='simulation', run_id=run_id))
                    step += 1
                    await asyncio.sleep(STEP_SECONDS)
        except asyncio.CancelledError:
            status = 'cancelled'
        except Exception:
            logging.getLogger(__name__).exception('Scenario failed: %s', run_id)
            status = 'failed'
        finally:
            async with self.app.state.db.sessions() as session:
                await session.execute(update(ScenarioRun).where(ScenarioRun.id == run_id).values(
                    status=status, finished_at=utcnow()))
                await session.commit()

    async def stop(self, run_id):
        task = self.tasks.get(run_id)
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def close(self):
        for task in list(self.tasks.values()):
            task.cancel()
        await asyncio.gather(*list(self.tasks.values()), return_exceptions=True)
