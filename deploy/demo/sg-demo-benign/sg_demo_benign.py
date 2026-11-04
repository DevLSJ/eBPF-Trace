"""sg-demo-benign — 시연용 정상 패키지(대조군). 가져와도 아무 일도 하지 않는다."""

__version__ = "1.0.0"


def hello(name="SupplyGuard"):
    return f"hello, {name}"
