import pytest
from unittest.mock import patch, MagicMock
from app.engines.c2 import infra_enricher, graph_builder

def test_infra_enricher_private_ip():
    """Test enrichment of a private IP address."""
    result = infra_enricher.enrich_ip("192.168.1.1")
    assert result["address"] == "192.168.1.1"
    assert result["is_private"] is True
    assert result["provider"] == "Private Network"

def test_infra_enricher_known_cloud():
    """Test enrichment of a known AWS IP range."""
    result = infra_enricher.enrich_ip("54.1.2.3")
    assert result["address"] == "54.1.2.3"
    assert result["is_private"] is False
    assert result["provider"] == "Amazon AWS"
    assert result["country"] == "US"

def test_infra_enricher_suspicious_domain():
    """Test enrichment of a suspicious TLD domain."""
    result = infra_enricher.enrich_domain("malware-c2.tk")
    assert result["domain"] == "malware-c2.tk"
    assert result["suspicious_tld"] is True
    assert result["tld"] == ".tk"
    assert any("Suspicious TLD" in indicator for indicator in result["risk_indicators"])

def test_infra_enricher_dga_domain():
    """Test enrichment of a DGA-like domain."""
    result = infra_enricher.enrich_domain("xkjqwdzbp9921.com")
    assert result["domain"] == "xkjqwdzbp9921.com"
    assert any("DGA" in indicator for indicator in result["risk_indicators"])

def test_graph_builder_empty_case(tmp_path):
    """With no IOCs, the graph still contains the central APK node."""
    case_dir = tmp_path / "case_1"
    case_dir.mkdir()

    result = graph_builder.build_c2_graph(
        case_dir=str(case_dir),
        apk_hash="dummyhash",
        package_name="com.test.app",
    )

    assert result["status"] == "success"
    assert result["total_nodes"] >= 1
    apk_nodes = [n for n in result["nodes"] if n["type"] == "apk"]
    assert len(apk_nodes) == 1
    assert apk_nodes[0]["metadata"]["hash"] == "dummyhash"


def test_graph_builder_includes_iocs(tmp_path):
    """Domains/IPs from the static IOC list become nodes linked to the APK."""
    import json
    case_dir = tmp_path / "case_2"
    (case_dir / "static_analysis").mkdir(parents=True)
    (case_dir / "static_analysis" / "ioc_list.json").write_text(json.dumps({
        "domains": ["malware-c2.tk"],
        "ips": ["8.8.8.8"],
        "urls": [],
    }))

    result = graph_builder.build_c2_graph(
        case_dir=str(case_dir), apk_hash="h2", package_name="com.bad.app"
    )

    assert result["status"] == "success"
    labels = {n["label"] for n in result["nodes"]}
    assert "malware-c2.tk" in labels
    # Suspicious TLD must be captured by the enricher and raise the node risk
    dom = next(n for n in result["nodes"] if n["label"] == "malware-c2.tk")
    assert dom["metadata"]["enrichment"]["suspicious_tld"] is True
    assert dom["risk"] in ("high", "critical")
    assert result["total_edges"] >= 1
