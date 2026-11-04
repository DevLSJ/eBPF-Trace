"""시연용 정상 패키지 — sg-demo-benign (정상 설치 대조군, 11/04).

평범한 순수 파이썬 패키지다. 설치 중에 하는 일은 setuptools 빌드뿐이다:
  - 자기 소스 파일을 읽고 빌드 디렉터리에 쓴다.
  - 다른 프로그램을 실행하지 않고, 스스로 네트워크에 접속하지 않으며, 자격 증명 · 계정 파일을 열지 않는다.
  - pip 가 빌드 도구(setuptools)를 받으려고 pypi.org · files.pythonhosted.org 에 접속하는 것은 pip 의 정상 동작이다.

SupplyGuard 기본 정책에서 위반 없이 「통과」로 끝나야 한다 — 같은 설치 샌드박스에서 reqeusts 와 나란히 보여 주는 대조군.
    sg-install pip ./deploy/demo/sg-demo-benign
"""
from setuptools import setup

setup(
    name="sg-demo-benign",
    version="1.0.0",
    description="SupplyGuard demo: a harmless package that installs cleanly (control group)",
    py_modules=["sg_demo_benign"],
)
