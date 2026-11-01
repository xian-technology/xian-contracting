from contracting.storage.lmdb_environment import LMDBEnvironmentOptions, LMDBEnvironmentPool


def test_existing_reader_never_opens_absent_storage(tmp_path):
    pool = LMDBEnvironmentPool()
    path = tmp_path / "absent"
    assert pool.read_existing_value(path, b"policy") is None
    assert not path.exists()


def test_existing_reader_preserves_environment_and_releases_temporary_lease(tmp_path):
    pool = LMDBEnvironmentPool()
    lease = pool.acquire(tmp_path, LMDBEnvironmentOptions(map_size=1048576))
    try:
        with lease.env.begin(write=True) as transaction:
            transaction.put(b"policy", b"current")
        before = (tmp_path / "data.mdb").read_bytes()
        size = lease.env.info()["map_size"]
        assert pool.read_existing_value(tmp_path, b"policy") == (b"current", 1)
        assert pool.read_existing_value(tmp_path, b"missing") == (None, 1)
        assert pool.ref_count(tmp_path) == 1
        assert lease.env.info()["map_size"] == size
        assert (tmp_path / "data.mdb").read_bytes() == before
    finally:
        lease.close()
    assert pool.ref_count(tmp_path) == 0
    assert pool.read_existing_value(tmp_path, b"policy") is None
