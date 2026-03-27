"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc Copyright end
"""

import requests
import json

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('socradar')

status_map = {
    "OPEN": 0,
    "INVESTIGATING": 1,
    "RESOLVED": 2,
    "PENDING_INFO": 4,
    "LEGAL_REVIEW": 5,
    "VENDOR_ASSESSMENT": 6,
    "FALSE_POSITIVE": 9,
    "DUPLICATE": 10,
    "PROCESSED_INTERNALLY": 11,
    "NOT_APPLICABLE": 13,
    "MITIGATED": 12
}


def _get_config(config):
    return (
        config.get("url", "").replace("\"", "").strip(),
        config.get("company_id"),
        config.get("company_key", "").strip(),
        config.get("verify", True),
    )


def _headers(company_key):
    return {"API-KEY": company_key}


def _parse(response):
    content = json.loads(response.text)
    return content.get("data", content)


# ---------------------------------------------------------------------------
# Existing operations
# ---------------------------------------------------------------------------

def threat_analysis(config, params):
    key = config.get("threat_analysis_api_key", "").replace("\"", "").strip()
    url, _, _, verify = _get_config(config)
    entity = params.get("entity", "").replace("\"", "").strip()
    advance_investigation = params.get("advance_investigation")
    force_new_analysis = params.get("force_new_analysis")
    try:
        response = requests.get(
            f"{url}/threat/analysis",
            params={"key": key, "entity": entity,
                    "advance_investigation": advance_investigation,
                    "force_new_analysis": force_new_analysis},
            verify=verify)
        return json.loads(response.text).get("data")
    except Exception as e:
        logger.error(f"SOCRadar returned error: {str(e)}")
        raise ConnectorError("{0}".format(e))


def get_incidents(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/incidents/v4",
            params={"start_date": params.get("start_date"),
                    "end_date": params.get("end_date"),
                    "status": params.get("status"),
                    "limit": params.get("limit"),
                    "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        logger.error(f"SOCRadar returned error: {str(e)}")
        raise ConnectorError("{0}".format(e))


def get_incident(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/incidents/v4",
            params={"alarm_ids": params.get("alarm_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        logger.error(f"SOCRadar returned error: {str(e)}")
        raise ConnectorError("{0}".format(e))


def change_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    alarm_id = params.get("alarm_id")
    status = status_map[params.get("status")]
    comment = params.get("comment")
    try:
        response = requests.post(
            f"{url}/company/{company_id}/alarms/status/change",
            data={"alarm_ids": alarm_id, "status": status, "comment": comment},
            headers=_headers(company_key), verify=verify)
        return json.loads(response.text)
    except Exception as e:
        logger.error(f"SOCRadar returned error: {e}")
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Incident API V4 — remaining endpoints
# ---------------------------------------------------------------------------

def post_alarm_comment(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/alarm/add/comment/v2",
            json={"alarm_id": params.get("alarm_id"), "comment": params.get("comment")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def ask_to_analyst_v2(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/incidents/ask/analyst/v2",
            json={"alarm_id": params.get("alarm_id"), "message": params.get("message")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_assignee(config, params):
    url, company_id, company_key, verify = _get_config(config)
    alarm_id = params.get("alarm_id")
    try:
        response = requests.get(
            f"{url}/company/{company_id}/alarm/{alarm_id}/assignee",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def change_assignee(config, params):
    url, company_id, company_key, verify = _get_config(config)
    alarm_id = params.get("alarm_id")
    try:
        response = requests.post(
            f"{url}/company/{company_id}/alarm/{alarm_id}/assignee",
            json={"assignee_id": params.get("assignee_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def change_severity(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/alarm/severity",
            json={"alarm_id": params.get("alarm_id"), "severity": params.get("severity")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_assignee_options(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/alarm/assignee_options",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_remove_tag(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/alarm/tag",
            json={"alarm_id": params.get("alarm_id"),
                  "tag": params.get("tag"),
                  "action": params.get("action")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Threat Analysis — remaining endpoints
# ---------------------------------------------------------------------------

def get_threat_analysis_result(config, params):
    key = config.get("threat_analysis_api_key", "").replace("\"", "").strip()
    url, _, _, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threat/analysis/result",
            params={"key": key, "entity": params.get("entity")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_triggered_analysis_list(config, params):
    key = config.get("threat_analysis_api_key", "").replace("\"", "").strip()
    url, _, _, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threat/analysis/get/triggered/analysis",
            params={"key": key, "limit": params.get("limit"), "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# IoC Enrichment
# ---------------------------------------------------------------------------

def get_indicator_details(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/ioc_enrichment/get/indicator_details",
            params={"key": company_key, "indicator": params.get("indicator")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_indicator_details_stix(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/ioc_enrichment/get/indicator_details_stix",
            params={"key": company_key, "indicator": params.get("indicator")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# CTI Threat Hunting Rules
# ---------------------------------------------------------------------------

def search_threat_hunting_rules(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threathunting_rule/search",
            params={"key": company_key, "query": params.get("query"),
                    "limit": params.get("limit"), "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def download_threat_hunting_rules(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threathunting_rule/download",
            params={"key": company_key, "rule_id": params.get("rule_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# CTI ThreatHunting
# ---------------------------------------------------------------------------

def query_threat_data(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/threathose/query",
            json={"query": params.get("query"),
                  "limit": params.get("limit"),
                  "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_threat_content_details(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/threathose/content/details",
            json={"id": params.get("content_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def threat_investigating(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/threathose/query/extended",
            params={"key": company_key},
            json={"query": params.get("query"),
                  "limit": params.get("limit"),
                  "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# CTI Vulnerability Intelligence
# ---------------------------------------------------------------------------

def search_vulnerabilities(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/vulnerability/search_vulnerabilities",
            params={"key": company_key, "query": params.get("query"),
                    "limit": params.get("limit"), "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def search_vulnerabilities_v2(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/vulnerability/search_vulnerabilities/v2",
            params={"key": company_key, "query": params.get("query"),
                    "limit": params.get("limit"), "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_cve_trends(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/vulnerability/get_cve_trends",
            params={"key": company_key},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_cve_details(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/vulnerability/cve_details",
            params={"key": company_key, "cve_id": params.get("cve_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_cve_tweets(config, params):
    url, _, company_key, verify = _get_config(config)
    cve = params.get("cve")
    try:
        response = requests.get(
            f"{url}/vulnerability/cve/{cve}/tweets",
            params={"key": company_key},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_cve_dorks(config, params):
    url, _, company_key, verify = _get_config(config)
    cve = params.get("cve")
    try:
        response = requests.get(
            f"{url}/vulnerability/cve/{cve}/dorks",
            params={"key": company_key},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_cve_news(config, params):
    url, _, company_key, verify = _get_config(config)
    cve = params.get("cve")
    try:
        response = requests.get(
            f"{url}/vulnerability/cve/{cve}/news",
            params={"key": company_key},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_cve_iocs(config, params):
    url, _, company_key, verify = _get_config(config)
    cve = params.get("cve")
    try:
        response = requests.get(
            f"{url}/vulnerability/cve/{cve}/iocs",
            params={"key": company_key},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# CTI Rapid Reputation
# ---------------------------------------------------------------------------

def get_rapid_reputation(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threatfeed/rapid/reputation",
            params={"key": company_key, "entity": params.get("entity")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Threat Actor Malware
# ---------------------------------------------------------------------------

def get_threat_actors(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threat/actors/get_actors",
            params={"key": company_key,
                    "limit": params.get("limit"),
                    "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_actor_detail(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threat/actors/get_actor_detail",
            params={"key": company_key, "actor_id": params.get("actor_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_actor_detailed_content(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threat/actors/get/detailed_content",
            params={"key": company_key, "actor_id": params.get("actor_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_actor_param_options(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threat/actors/param_options",
            params={"key": company_key},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# ASM Vulnerabilities V2
# ---------------------------------------------------------------------------

def get_latest_vulnerabilities_v2(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/vulnerabilities/v2/latest",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_latest_mobile_app_security(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/vulnerabilities/v2/latest_mobile_application_security",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# ASM Digital Footprint
# ---------------------------------------------------------------------------

def get_all_assets(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/asm",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_all_assets_v2(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/asm/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_asset_details(config, params):
    url, company_id, company_key, verify = _get_config(config)
    asset_type = params.get("asset_type")
    try:
        response = requests.get(
            f"{url}/company/{company_id}/asset_details/{asset_type}",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_assets(config, params):
    url, company_id, company_key, verify = _get_config(config)
    asset_type = params.get("asset_type")
    try:
        response = requests.post(
            f"{url}/company/{company_id}/asm/add/{asset_type}",
            json={"assets": params.get("assets")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def exclude_asset(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/asm/fp",
            json={"asset_id": params.get("asset_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def configure_monitoring(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/asm/monitor",
            json={"asset_id": params.get("asset_id"), "monitoring": params.get("monitoring")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def download_website_uptime_checks(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/asm/website/download_website_uptime_checks",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def change_uptime_check_location(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/asm/website/change/uptime_check_location",
            json={"asset_id": params.get("asset_id"), "location": params.get("location")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Brand Protection V2
# ---------------------------------------------------------------------------

def get_impersonating_accounts(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/brand-protection/impersonating-accounts/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_impersonating_domains(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/brand-protection/impersonating-domains/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_rogue_mobile_applications(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/brand-protection/rogue-mobile-applications/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_bad_reputation_data(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/brand-protection/bad-reputation/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_social_media_findings(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/brand-protection/social-media-findings/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_phishing_domains(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/phishing_domain/add",
            json={"domains": params.get("domains")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_impersonating_account(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/impersonating-account/add",
            json={"account": params.get("account")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_rogue_mobile_application(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/rogue-mobile-application/add",
            json={"app": params.get("app")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_social_media_finding(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/social-media-findings/add",
            json={"finding": params.get("finding")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_impersonating_domains_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/impersonating-domains/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_bad_reputation_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/bad-reputation/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_rogue_mobile_app_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/rogue-mobile-apps/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_impersonating_account_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/impersonating-account/status-change",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_social_media_findings_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/social-media-findings/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Dark Web Monitoring V2
# ---------------------------------------------------------------------------

def get_botnet_data_v2(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/dark-web-monitoring/botnet-data/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_black_market_v2(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/dark-web-monitoring/black-market/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_suspicious_content_v2(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/dark-web-monitoring/suspicious-content/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_pii_exposure_v2(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/dark-web-monitoring/pii-exposure/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_im_content_v2(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/dark-web-monitoring/im-content/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_botnet_data_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/dark-web-monitoring/botnet-data/status-change",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_black_market_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/dark-web-monitoring/black-market/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_suspicious_content_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/dark-web-monitoring/suspicious-content/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_pii_exposure_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/dark-web-monitoring/pii-exposure/status-change",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_im_content_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/dark-web-monitoring/im-content/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def post_request_obtain(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/dark-web-monitoring/request-obtain",
            json={"data_id": params.get("data_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Identity Access Intelligence
# ---------------------------------------------------------------------------

def info_stealer_search(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/query",
            params={"key": company_key},
            json={"query": params.get("query"),
                  "limit": params.get("limit"),
                  "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def info_stealer_download_credentials(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/query_details/credentials/download",
            params={"key": company_key},
            json={"query_id": params.get("query_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def info_stealer_download_info_file(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/query_details/info_file/download",
            params={"key": company_key},
            json={"query_id": params.get("query_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def breach_query(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/breach/query",
            params={"key": company_key},
            json={"query": params.get("query"),
                  "limit": params.get("limit"),
                  "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def breaches_download(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/breaches/download",
            params={"key": company_key},
            json={"breach_id": params.get("breach_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def info_stealer_file_tree(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/file-tree",
            params={"key": company_key},
            json={"query_id": params.get("query_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def stealer_logs_on_sale_query(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/stealer_logs_on_sale/query",
            params={"key": company_key},
            json={"query": params.get("query"),
                  "limit": params.get("limit"),
                  "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def stealer_logs_on_sale_download(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/stealer_logs_on_sale/download",
            params={"key": company_key},
            json={"log_id": params.get("log_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def stealer_logs_on_sale_decompose(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/stealer_logs_on_sale/decompose_content",
            params={"key": company_key},
            json={"log_id": params.get("log_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def stealer_logs_on_sale_full_content(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/identity/intelligence/stealer_logs_on_sale/full_content",
            params={"key": company_key},
            json={"log_id": params.get("log_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Company Identity (User) Management
# ---------------------------------------------------------------------------

def get_user_roles(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company_identity_management/get_user_roles",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_users(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company_identity_management/get_users",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def create_user(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company_identity_management/create_user",
            json={"email": params.get("email"),
                  "name": params.get("name"),
                  "role_ids": params.get("role_ids")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def enable_user(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company_identity_management/enable_user",
            json={"user_id": params.get("user_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def disable_user(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company_identity_management/disable_user",
            json={"user_id": params.get("user_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def delete_user(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company_identity_management/delete_user",
            json={"user_id": params.get("user_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_roles_to_user(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company_identity_management/add_roles_to_user",
            json={"user_id": params.get("user_id"), "role_ids": params.get("role_ids")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def delete_roles_from_user(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company_identity_management/delete_roles_to_user",
            json={"user_id": params.get("user_id"), "role_ids": params.get("role_ids")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def enable_user_sso(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company_identity_management/enable_user_sso",
            json={"user_id": params.get("user_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def disable_user_sso(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company_identity_management/disable_user_sso",
            json={"user_id": params.get("user_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Company Allowlist
# ---------------------------------------------------------------------------

def get_allowlist_entities(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threatfeed/whitelist/get/{company_id}",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_allowlist_entity(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/threatfeed/whitelist/add/{company_id}",
            json={"entity": params.get("entity"), "entity_type": params.get("entity_type")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def upload_allowlist_file(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/threatfeed/whitelist/upload/{company_id}",
            json={"file_content": params.get("file_content")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def delete_allowlist_entity(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.delete(
            f"{url}/threatfeed/whitelist/delete/{company_id}",
            json={"entity_id": params.get("entity_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Company Pocket
# ---------------------------------------------------------------------------

def get_company_pocket_data(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threatfeed/company_pocket/{company_id}",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_company_pocket_indicators(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/threatfeed/company_pocket/{company_id}",
            json={"indicators": params.get("indicators")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def upload_company_pocket_file(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/threatfeed/company_pocket/{company_id}/upload",
            json={"file_content": params.get("file_content")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def delete_company_pocket_entities(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.delete(
            f"{url}/threatfeed/company_pocket/{company_id}",
            json={"entity_ids": params.get("entity_ids")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Takedown
# ---------------------------------------------------------------------------

def submit_phishing_takedown(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/add/company/{company_id}/takedown/request",
            json={"domain_or_url": params.get("domain_or_url")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def submit_rogue_mobile_app_takedown(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/add/company/{company_id}/takedown/request/rogue_mobile_apps",
            json={"app_id": params.get("app_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def submit_social_media_takedown(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/add/company/{company_id}/takedown/request/social_media_risks",
            json={"finding_id": params.get("finding_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def submit_source_code_takedown(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/add/company/{company_id}/takedown/request/source_code_leaks",
            json={"leak_id": params.get("leak_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_takedown_progress(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/get/company/{company_id}/takedown/progress",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# VIP Protection V2
# ---------------------------------------------------------------------------

def get_vip_protection(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/vip-protection/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_vip_protection_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/vip-protection/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Surface Web Monitoring V2
# ---------------------------------------------------------------------------

def get_surface_web_monitoring(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/surface_web_monitoring/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_surface_web_monitoring_record(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/surface-web-monitoring/add",
            json={"url": params.get("record_url")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_surface_web_monitoring_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/brand-protection/surface-web-monitoring/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# DRP Fraud Protection V2
# ---------------------------------------------------------------------------

def get_fraud_protection_v2(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/fraud-protection/v2",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_fraud_protection_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/fraud-protection/status-update",
            json={"ids": params.get("ids"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Ransomware News
# ---------------------------------------------------------------------------

def get_ransomware_victims(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/ransomware/victims",
            params={"key": company_key,
                    "limit": params.get("limit"),
                    "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# CTI Dark Web News
# ---------------------------------------------------------------------------

def search_dark_web_news(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/darkweb/news",
            params={"key": company_key,
                    "query": params.get("query"),
                    "limit": params.get("limit"),
                    "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# CTI Source Code Leakage
# ---------------------------------------------------------------------------

def get_source_code_leakage(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/source/code/leakage",
            params={"key": company_key,
                    "query": params.get("query"),
                    "limit": params.get("limit"),
                    "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Malware Analysis
# ---------------------------------------------------------------------------

def analyze_malware_file(config, params):
    key = config.get("threat_analysis_api_key", "").replace("\"", "").strip()
    url, _, _, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/threat/analysis/file",
            params={"key": key},
            json={"file_content": params.get("file_content")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Combolists
# ---------------------------------------------------------------------------

def get_combo_lists(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/combolists/lists",
            params={"key": company_key,
                    "limit": params.get("limit"),
                    "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_combolist_details(config, params):
    url, _, company_key, verify = _get_config(config)
    combolist_uuid = params.get("combolist_uuid")
    try:
        response = requests.get(
            f"{url}/combolists/detail/{combolist_uuid}",
            params={"key": company_key},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Advanced Fraud Detection
# ---------------------------------------------------------------------------

def search_fraud_card(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/fraud/card",
            params={"key": company_key},
            json={"card_number": params.get("card_number")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def lookup_bin(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/fraud/bin-lookup",
            params={"key": company_key, "bin": params.get("bin")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Premium Feeds
# ---------------------------------------------------------------------------

def list_premium_feeds(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/premium-feeds/{company_id}/list-premium-feeds",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_premium_feed_content(config, params):
    url, company_id, company_key, verify = _get_config(config)
    feed_uuid = params.get("feed_uuid")
    feed_format = params.get("feed_format")
    try:
        response = requests.get(
            f"{url}/premium-feeds/{company_id}/get/{feed_uuid}/{feed_format}",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Company Events
# ---------------------------------------------------------------------------

def get_company_events(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/events",
            params={"start_date": params.get("start_date"),
                    "end_date": params.get("end_date"),
                    "limit": params.get("limit"),
                    "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Company User Audit Logs
# ---------------------------------------------------------------------------

def get_company_audit_logs(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/auditlogs",
            params={"key": company_key,
                    "limit": params.get("limit"),
                    "page": params.get("page")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Collection Based IOC Feed
# ---------------------------------------------------------------------------

def get_ioc_feed(config, params):
    url, _, company_key, verify = _get_config(config)
    collection_uuid = params.get("collection_uuid")
    feed_format = params.get("feed_format")
    try:
        response = requests.get(
            f"{url}/threat/intelligence/feed_list/{collection_uuid}.{feed_format}",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Company Supply Chain Reports
# ---------------------------------------------------------------------------

def get_supply_chain_report(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/supply_chain/report",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# DRP Configuration
# ---------------------------------------------------------------------------

def get_drp_configuration_assets(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/drp-configuration/assets",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def add_drp_asset(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/drp-configuration/assets/add",
            json={"asset": params.get("asset"), "asset_type": params.get("asset_type")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_drp_monitoring_status(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/drp-configuration/assets/update/monitoring-status",
            json={"asset_id": params.get("asset_id"), "status": params.get("status")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Referrer Log
# ---------------------------------------------------------------------------

def post_referrer_logs(config, params):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.post(
            f"{url}/company/{company_id}/referrer_logs/submit",
            json={"referrer_data": params.get("referrer_data")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# CTI Threat Feed
# ---------------------------------------------------------------------------

def get_feed_sources(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threatfeed/feed_sources",
            params={"key": company_key},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_feed_source_details(config, params):
    url, _, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/threatfeed/feed_sources/details",
            params={"key": company_key, "feed_id": params.get("feed_id")},
            verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Multi-Tenant Management
# ---------------------------------------------------------------------------

def _mt_url(config):
    url, _, company_key, verify = _get_config(config)
    multi_tenant_id = config.get("multi_tenant_id")
    return url, multi_tenant_id, company_key, verify


def create_tenant(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/create",
            json=params, headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def extend_tenant_subscription(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/{tenant_id}/extend-subscription",
            json={"end_date": params.get("end_date")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def archive_tenant(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/{tenant_id}/archive",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def unarchive_tenant(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/{tenant_id}/unarchive",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_tenant_settings(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.patch(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/{tenant_id}/settings",
            json={"settings": params.get("settings")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_tenant_service_config(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.patch(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/{tenant_id}/service-configuration",
            json={"config": params.get("config")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_tenant_detail(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/{tenant_id}/detail",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_tenant_history(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/{tenant_id}/history",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def list_tenants(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/list",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def change_tenant_ecosystem(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/change-ecosystem",
            json={"tenant_id": params.get("tenant_id"),
                  "ecosystem_id": params.get("ecosystem_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_multi_tenant_param_options(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/parameter-options",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def list_ecosystems(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/ecosystem/list",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def create_ecosystem(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/ecosystem/create",
            json={"name": params.get("name")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def delete_ecosystem(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    ecosystem_id = params.get("ecosystem_id")
    try:
        response = requests.delete(
            f"{url}/v1/multi-tenant/{mt_id}/ecosystem/{ecosystem_id}/delete",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_ecosystem_name(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    ecosystem_id = params.get("ecosystem_id")
    try:
        response = requests.patch(
            f"{url}/v1/multi-tenant/{mt_id}/ecosystem/{ecosystem_id}/update",
            json={"name": params.get("name")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_multi_tenant_incidents(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/incidents",
            params={"limit": params.get("limit"), "page": params.get("page")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def get_tenant_settings_details(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/settings/details",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def download_asset_sizing(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/download-asset-sizing",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def calculate_asset_sizing(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/calculate-asset-sizing",
            json={"asset_count": params.get("asset_count")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def create_tenant_template(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/create-template",
            json={"template": params.get("template")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def list_tenant_templates(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/tenant/templates",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def list_multi_tenant_users(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/user/list",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def list_tenant_company_users(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.get(
            f"{url}/v1/multi-tenant/{mt_id}/user/{tenant_id}/list",
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def create_multi_tenant_user(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/user/create",
            json={"email": params.get("email"), "name": params.get("name")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def update_multi_tenant_user(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    try:
        response = requests.patch(
            f"{url}/v1/multi-tenant/{mt_id}/user/update",
            json=params,
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def assign_user_to_tenant(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.post(
            f"{url}/v1/multi-tenant/{mt_id}/user/{tenant_id}/assign",
            json={"user_id": params.get("user_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


def unassign_user_from_tenant(config, params):
    url, mt_id, company_key, verify = _mt_url(config)
    tenant_id = params.get("tenant_id")
    try:
        response = requests.delete(
            f"{url}/v1/multi-tenant/{mt_id}/user/{tenant_id}/unassign",
            json={"user_id": params.get("user_id")},
            headers=_headers(company_key), verify=verify)
        return _parse(response)
    except Exception as e:
        raise ConnectorError("{0}".format(e))


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def _check_health(config):
    url, company_id, company_key, verify = _get_config(config)
    try:
        response = requests.get(
            f"{url}/company/{company_id}/auditlogs",
            params={"key": company_key, "limit": 1},
            verify=verify)
        if response.status_code != 200:
            raise ConnectorError("Unable to connect SOCRadar")
        return True
    except Exception as e:
        raise ConnectorError("Unable to connect SOCRadar {0}".format(e))


# ---------------------------------------------------------------------------
# Operations registry
# ---------------------------------------------------------------------------

operations = {
    # Original
    "get_incidents": get_incidents,
    "get_incident": get_incident,
    "threat_analysis": threat_analysis,
    "change_status": change_status,
    # Incident V4 completion
    "post_alarm_comment": post_alarm_comment,
    "ask_to_analyst_v2": ask_to_analyst_v2,
    "get_assignee": get_assignee,
    "change_assignee": change_assignee,
    "change_severity": change_severity,
    "get_assignee_options": get_assignee_options,
    "add_remove_tag": add_remove_tag,
    # Threat Analysis completion
    "get_threat_analysis_result": get_threat_analysis_result,
    "get_triggered_analysis_list": get_triggered_analysis_list,
    # IoC Enrichment
    "get_indicator_details": get_indicator_details,
    "get_indicator_details_stix": get_indicator_details_stix,
    # CTI Threat Hunting Rules
    "search_threat_hunting_rules": search_threat_hunting_rules,
    "download_threat_hunting_rules": download_threat_hunting_rules,
    # CTI ThreatHunting
    "query_threat_data": query_threat_data,
    "get_threat_content_details": get_threat_content_details,
    "threat_investigating": threat_investigating,
    # CTI Vulnerability Intelligence
    "search_vulnerabilities": search_vulnerabilities,
    "search_vulnerabilities_v2": search_vulnerabilities_v2,
    "get_cve_trends": get_cve_trends,
    "get_cve_details": get_cve_details,
    "get_cve_tweets": get_cve_tweets,
    "get_cve_dorks": get_cve_dorks,
    "get_cve_news": get_cve_news,
    "get_cve_iocs": get_cve_iocs,
    # CTI Rapid Reputation
    "get_rapid_reputation": get_rapid_reputation,
    # Threat Actor Malware
    "get_threat_actors": get_threat_actors,
    "get_actor_detail": get_actor_detail,
    "get_actor_detailed_content": get_actor_detailed_content,
    "get_actor_param_options": get_actor_param_options,
    # ASM Vulnerabilities V2
    "get_latest_vulnerabilities_v2": get_latest_vulnerabilities_v2,
    "get_latest_mobile_app_security": get_latest_mobile_app_security,
    # ASM Digital Footprint
    "get_all_assets": get_all_assets,
    "get_all_assets_v2": get_all_assets_v2,
    "get_asset_details": get_asset_details,
    "add_assets": add_assets,
    "exclude_asset": exclude_asset,
    "configure_monitoring": configure_monitoring,
    "download_website_uptime_checks": download_website_uptime_checks,
    "change_uptime_check_location": change_uptime_check_location,
    # Brand Protection V2
    "get_impersonating_accounts": get_impersonating_accounts,
    "get_impersonating_domains": get_impersonating_domains,
    "get_rogue_mobile_applications": get_rogue_mobile_applications,
    "get_bad_reputation_data": get_bad_reputation_data,
    "get_social_media_findings": get_social_media_findings,
    "add_phishing_domains": add_phishing_domains,
    "add_impersonating_account": add_impersonating_account,
    "add_rogue_mobile_application": add_rogue_mobile_application,
    "add_social_media_finding": add_social_media_finding,
    "update_impersonating_domains_status": update_impersonating_domains_status,
    "update_bad_reputation_status": update_bad_reputation_status,
    "update_rogue_mobile_app_status": update_rogue_mobile_app_status,
    "update_impersonating_account_status": update_impersonating_account_status,
    "update_social_media_findings_status": update_social_media_findings_status,
    # Dark Web Monitoring V2
    "get_botnet_data_v2": get_botnet_data_v2,
    "get_black_market_v2": get_black_market_v2,
    "get_suspicious_content_v2": get_suspicious_content_v2,
    "get_pii_exposure_v2": get_pii_exposure_v2,
    "get_im_content_v2": get_im_content_v2,
    "update_botnet_data_status": update_botnet_data_status,
    "update_black_market_status": update_black_market_status,
    "update_suspicious_content_status": update_suspicious_content_status,
    "update_pii_exposure_status": update_pii_exposure_status,
    "update_im_content_status": update_im_content_status,
    "post_request_obtain": post_request_obtain,
    # Identity Access Intelligence
    "info_stealer_search": info_stealer_search,
    "info_stealer_download_credentials": info_stealer_download_credentials,
    "info_stealer_download_info_file": info_stealer_download_info_file,
    "breach_query": breach_query,
    "breaches_download": breaches_download,
    "info_stealer_file_tree": info_stealer_file_tree,
    "stealer_logs_on_sale_query": stealer_logs_on_sale_query,
    "stealer_logs_on_sale_download": stealer_logs_on_sale_download,
    "stealer_logs_on_sale_decompose": stealer_logs_on_sale_decompose,
    "stealer_logs_on_sale_full_content": stealer_logs_on_sale_full_content,
    # Company Identity Management
    "get_user_roles": get_user_roles,
    "get_users": get_users,
    "create_user": create_user,
    "enable_user": enable_user,
    "disable_user": disable_user,
    "delete_user": delete_user,
    "add_roles_to_user": add_roles_to_user,
    "delete_roles_from_user": delete_roles_from_user,
    "enable_user_sso": enable_user_sso,
    "disable_user_sso": disable_user_sso,
    # Allowlist
    "get_allowlist_entities": get_allowlist_entities,
    "add_allowlist_entity": add_allowlist_entity,
    "upload_allowlist_file": upload_allowlist_file,
    "delete_allowlist_entity": delete_allowlist_entity,
    # Company Pocket
    "get_company_pocket_data": get_company_pocket_data,
    "add_company_pocket_indicators": add_company_pocket_indicators,
    "upload_company_pocket_file": upload_company_pocket_file,
    "delete_company_pocket_entities": delete_company_pocket_entities,
    # Takedown
    "submit_phishing_takedown": submit_phishing_takedown,
    "submit_rogue_mobile_app_takedown": submit_rogue_mobile_app_takedown,
    "submit_social_media_takedown": submit_social_media_takedown,
    "submit_source_code_takedown": submit_source_code_takedown,
    "get_takedown_progress": get_takedown_progress,
    # VIP Protection V2
    "get_vip_protection": get_vip_protection,
    "update_vip_protection_status": update_vip_protection_status,
    # Surface Web Monitoring V2
    "get_surface_web_monitoring": get_surface_web_monitoring,
    "add_surface_web_monitoring_record": add_surface_web_monitoring_record,
    "update_surface_web_monitoring_status": update_surface_web_monitoring_status,
    # DRP Fraud Protection V2
    "get_fraud_protection_v2": get_fraud_protection_v2,
    "update_fraud_protection_status": update_fraud_protection_status,
    # Ransomware News
    "get_ransomware_victims": get_ransomware_victims,
    # CTI Dark Web News
    "search_dark_web_news": search_dark_web_news,
    # CTI Source Code Leakage
    "get_source_code_leakage": get_source_code_leakage,
    # Malware Analysis
    "analyze_malware_file": analyze_malware_file,
    # Combolists
    "get_combo_lists": get_combo_lists,
    "get_combolist_details": get_combolist_details,
    # Advanced Fraud Detection
    "search_fraud_card": search_fraud_card,
    "lookup_bin": lookup_bin,
    # Premium Feeds
    "list_premium_feeds": list_premium_feeds,
    "get_premium_feed_content": get_premium_feed_content,
    # Company Events
    "get_company_events": get_company_events,
    # Company User Audit Logs
    "get_company_audit_logs": get_company_audit_logs,
    # Collection Based IOC Feed
    "get_ioc_feed": get_ioc_feed,
    # Company Supply Chain Reports
    "get_supply_chain_report": get_supply_chain_report,
    # DRP Configuration
    "get_drp_configuration_assets": get_drp_configuration_assets,
    "add_drp_asset": add_drp_asset,
    "update_drp_monitoring_status": update_drp_monitoring_status,
    # Referrer Log
    "post_referrer_logs": post_referrer_logs,
    # CTI Threat Feed
    "get_feed_sources": get_feed_sources,
    "get_feed_source_details": get_feed_source_details,
    # Multi-Tenant Management
    "create_tenant": create_tenant,
    "extend_tenant_subscription": extend_tenant_subscription,
    "archive_tenant": archive_tenant,
    "unarchive_tenant": unarchive_tenant,
    "update_tenant_settings": update_tenant_settings,
    "update_tenant_service_config": update_tenant_service_config,
    "get_tenant_detail": get_tenant_detail,
    "get_tenant_history": get_tenant_history,
    "list_tenants": list_tenants,
    "change_tenant_ecosystem": change_tenant_ecosystem,
    "get_multi_tenant_param_options": get_multi_tenant_param_options,
    "list_ecosystems": list_ecosystems,
    "create_ecosystem": create_ecosystem,
    "delete_ecosystem": delete_ecosystem,
    "update_ecosystem_name": update_ecosystem_name,
    "get_multi_tenant_incidents": get_multi_tenant_incidents,
    "get_tenant_settings_details": get_tenant_settings_details,
    "download_asset_sizing": download_asset_sizing,
    "calculate_asset_sizing": calculate_asset_sizing,
    "create_tenant_template": create_tenant_template,
    "list_tenant_templates": list_tenant_templates,
    "list_multi_tenant_users": list_multi_tenant_users,
    "list_tenant_company_users": list_tenant_company_users,
    "create_multi_tenant_user": create_multi_tenant_user,
    "update_multi_tenant_user": update_multi_tenant_user,
    "assign_user_to_tenant": assign_user_to_tenant,
    "unassign_user_from_tenant": unassign_user_from_tenant,
}
