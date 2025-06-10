import pytest
from app.modules.sqli import SQLiModule

@pytest.fixture
def sqli_module():
    return SQLiModule()

def test_sqli_detection(sqli_module):
    # Test case 1: Simple SQL injection
    html = """
    <form action="/search" method="GET">
        <input type="text" name="q" value="' OR '1'='1">
    </form>
    """
    detections = sqli_module.analyze(html)
    assert len(detections) > 0
    assert any(d["type"] == "sql_injection" for d in detections)

def test_sqli_detection_complex(sqli_module):
    # Test case 2: Complex SQL injection with UNION
    html = """
    <form action="/search" method="POST">
        <input type="text" name="username" value="admin' UNION SELECT * FROM users--">
    </form>
    """
    detections = sqli_module.analyze(html)
    assert len(detections) > 0
    assert any(d["type"] == "sql_injection" for d in detections)

def test_sqli_detection_encoded(sqli_module):
    # Test case 3: URL encoded SQL injection
    html = """
    <form action="/search" method="GET">
        <input type="text" name="id" value="1%27%20OR%201%3D1--">
    </form>
    """
    detections = sqli_module.analyze(html)
    assert len(detections) > 0
    assert any(d["type"] == "sql_injection" for d in detections)

def test_sqli_detection_negative(sqli_module):
    # Test case 4: No SQL injection
    html = """
    <form action="/search" method="GET">
        <input type="text" name="q" value="normal search">
    </form>
    """
    detections = sqli_module.analyze(html)
    assert len(detections) == 0

def test_sqli_detection_multiple_inputs(sqli_module):
    # Test case 5: Multiple inputs with one SQL injection
    html = """
    <form action="/search" method="POST">
        <input type="text" name="username" value="normal">
        <input type="password" name="password" value="' OR '1'='1">
    </form>
    """
    detections = sqli_module.analyze(html)
    assert len(detections) > 0
    assert any(d["type"] == "sql_injection" for d in detections)
    assert any("password" in d["location"] for d in detections) 