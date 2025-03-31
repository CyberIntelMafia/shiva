from time import sleep
import requests
from integrations.base import BaseIntegration
import logging as logger

logger.getLogger(__name__)


class VTLookup(BaseIntegration):
    def __init__(self, api_key, threshold=5):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.__api_key = api_key
        self.threshold = int(threshold)
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Accept": "application/json",
                "x-apikey": self.__api_key,
            }
        )
        self._is_api_key_valid()

    def _is_api_key_valid(self):
        usage_endpoint = f"{self.base_url}/users/{self.__api_key}/api_usage"
        response = self._session.get(usage_endpoint)

        if response.status_code == 401:
            raise ValueError("Invalid API key.")

    def get_file_analysis(self, sha256: str):
        result, is_malicious = {}, False
        response = self.get_file_info(sha256)
        if not response:
            return result, is_malicious

        return self.analyze_result(response)

    def analyze_result(self, response: dict):
        is_malicious = self.is_file_malicious(
            response["data"]["attributes"]["last_analysis_stats"]
        )

        result = {
            "analysis_stats": response["data"]["attributes"]["last_analysis_stats"],
            "last_submission_date": response["data"]["attributes"][
                "last_submission_date"
            ],
            "last_analysis_date": response["data"]["attributes"]["last_analysis_date"],
        }
        return result, is_malicious

    def is_file_malicious(self, analysis_stats: dict) -> bool:
        malicious_count = analysis_stats.get("malicious", 0)
        suspicious_count = analysis_stats.get("suspicious", 0)
        if malicious_count >= self.threshold or suspicious_count >= self.threshold:
            return True

        return False

    def get_file_info(self, file_hash, retry=True):
        url = f"{self.base_url}/files/{file_hash}"
        try:
            r = self._session.get(url)
            if r.status_code == 200:
                response = r.json()
                return response
            if r.status_code == 401:
                logger.critical(f"Provide API key is invalid. Stopping analsysis")
            if r.status_code == 429:
                logger.critical(
                    f"Rate limit reached. Sleeping for 1 minute and retrying"
                )
                sleep(60)
                if retry:
                    self.get_file_info(file_hash, retry=False)
                else:
                    logger.critical(
                        f"Skipping attachment:{file_hash} due to ratelimiting."
                    )
        except Exception as e:
            logger.error(f"Failed to get file gets from VT for SHA256: {file_hash}")
