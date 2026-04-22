"""Virustotal file downloading helpers."""

import hashlib
import logging
import os.path

import httpx

logger = logging.getLogger("reportcollector")
VT_URL = "https://www.virustotal.com/vtapi/v2/"


class FileDownloader:
    """Download files from virustotal."""

    def __init__(self, apikey: str):
        """Create a new vt downloader with the given API Key."""
        self.apikey = apikey
        self.url_template = VT_URL + "file/download?apikey=" + apikey
        self.url_template += "&hash=%s"
        self.pcap_template = VT_URL + "file/network-traffic?apikey=" + apikey
        self.pcap_template += "&hash=%s"

    def hashcheck(self, filename: str, filehash: str) -> bool:
        """Return whether the hash-based filename matches it's contents."""
        algomap = {32: hashlib.md5, 40: hashlib.sha1, 64: hashlib.sha256}
        if len(filehash) not in algomap:
            raise Exception("File digest unexpected length (is it hex encoded?): %s" % filehash)
        algo = algomap[len(filehash)]()
        # Not chunking, no value currently.
        with open(filename, "rb") as tmp:
            algo.update(tmp.read())
        if filehash.lower() != algo.hexdigest():
            return False
        return True

    def _response_to_file(self, response: httpx.Response, outname: str):
        """Download repsonse content in chunks to outname."""
        with open(outname, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

    def download(self, filehash: str, outdir: str, pcap=True):
        """Download the selected filehash to the outdir."""
        outname = os.path.join(outdir, filehash)
        # check if already exists
        if os.path.exists(outname):
            if self.hashcheck(outname, filehash):
                logger.info("File already exists and matches hash... skipping download")
                return
            logger.info("File exists but hash mismatch.. re-downloading")

        url = self.url_template % filehash
        r = httpx.get(url, stream=True, timeout=30)
        r.raise_for_status()
        self._response_to_file(r, outname)

        logger.info("Successfully downloaded: %s", filehash)
        # attempt to get pcap as well
        if not pcap:
            return
        try:
            url = self.pcap_template % filehash
            r = httpx.get(url, stream=True, timeout=120)
            r.raise_for_status()
            # will return 200 with json for ok but not found
            if r.headers.get("content-type") != "application/cap":
                raise Exception("PCAP content not returned")
            self._response_to_file(r, outname + ".pcap")
        except Exception:
            logger.info("No PCAP found for sample: %s", filehash)
        else:
            logger.info("Successfully downloaded PCAP for: %s", filehash)
