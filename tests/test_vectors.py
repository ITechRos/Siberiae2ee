from siberiae2ee.hash import Streebog

def test_streebog_512_empty():
    expected = "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c9a0a8e1d0e2c0f8c4e6c0a8e4c8f2e1d0a8e4"
    result = Streebog.hash(b'', 512).hex()
    assert result == expected, f"Failed empty 512: {result}"

def test_streebog_512_abc():
    expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301730586281dcd3a"
    result = Streebog.hash(b"abc", 512).hex()
    assert result == expected, f"Failed 'abc' 512: {result}"

def test_streebog_256_empty():
    expected = "3f539a213e99d08c1a03aa9a7ea0aa87b4c8f0f7ddb7f6e8e1a4b2aa0e2f0b8b"
    result = Streebog.hash(b'', 256).hex()
    assert result == expected, f"Failed empty 256: {result}"

if __name__ == "__main__":
    test_streebog_512_empty()
    test_streebog_512_abc()
    test_streebog_256_empty()
    print("All test vectors passed!")