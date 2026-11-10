"""Cliente mínimo de la API REST de GitHub (solo biblioteca estándar)."""
import base64
import json
import re
import urllib.error
import urllib.request

API = "https://api.github.com"
_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class GitHubClient:
    def __init__(self, token):
        self._token = token

    def _open(self, url):
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "security-dashboard",
            },
        )
        return urllib.request.urlopen(request, timeout=30)

    @staticmethod
    def _unavailable(error):
        """404/403/451 = recurso no habilitado o sin permiso. Un límite de peticiones sí es un error."""
        if error.code == 403 and error.headers.get("X-RateLimit-Remaining") == "0":
            return False
        return error.code in (403, 404, 451)

    def get_json(self, path):
        """Un objeto JSON, o None si no está disponible."""
        try:
            with self._open(f"{API}{path}") as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if self._unavailable(error):
                return None
            raise

    def get_list(self, path):
        """Todas las páginas de una lista, o None si no está disponible."""
        url = f"{API}{path}?per_page=100"
        items = []
        while url:
            try:
                with self._open(url) as response:
                    items.extend(json.load(response))
                    match = _NEXT.search(response.headers.get("Link", ""))
                    url = match.group(1) if match else None
            except urllib.error.HTTPError as error:
                if self._unavailable(error):
                    return None
                raise
        return items

    def get_file_text(self, path):
        """Contenido de un archivo del repo, o None si no existe."""
        data = self.get_json(path)
        if not data or "content" not in data:
            return None
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
