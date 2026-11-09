from fmc_to_nac.nac import prune, ref_name, ref_names, ensure_domain


def test_prune_strips_metadata_and_empty():
    assert prune({"name": "x", "id": "1", "links": {}, "description": "", "overridable": False}) == {
        "name": "x",
        "overridable": False,
    }


def test_ref_helpers():
    assert ref_name({"name": "A", "id": "1"}) == "A"
    assert ref_names([{"name": "A"}, {"name": "B"}, "C"]) == ["A", "B", "C"]


def test_ensure_domain():
    model = {"fmc": {}}
    d = ensure_domain(model, "Global")
    d2 = ensure_domain(model, "Global")
    assert d is d2
    assert model["fmc"]["domains"] == [{"name": "Global"}]
