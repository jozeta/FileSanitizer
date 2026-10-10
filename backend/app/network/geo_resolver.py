import math
from typing import Dict, Any, Optional, Tuple
import httpx

from app.core.logging_config import logger

# Offline top world cities database for zero-network environments
# Format: (name, country, lat, lon)
OFFLINE_CITIES = [
    ("Stockholm", "Sweden", 59.3293, 18.0686),
    ("Gothenburg", "Sweden", 57.7089, 11.9746),
    ("Malmö", "Sweden", 55.6050, 13.0038),
    ("Oslo", "Norway", 59.9139, 10.7522),
    ("Copenhagen", "Denmark", 55.6761, 12.5683),
    ("Helsinki", "Finland", 60.1699, 24.9384),
    ("Reykjavik", "Iceland", 64.1466, -21.9426),
    ("London", "United Kingdom", 51.5074, -0.1278),
    ("Manchester", "United Kingdom", 53.4808, -2.2426),
    ("Edinburgh", "United Kingdom", 55.9533, -3.1883),
    ("Dublin", "Ireland", 53.3498, -6.2603),
    ("Paris", "France", 48.8566, 2.3522),
    ("Marseille", "France", 43.2965, 5.3698),
    ("Lyon", "France", 45.7640, 4.8357),
    ("Berlin", "Germany", 52.5200, 13.4050),
    ("Munich", "Germany", 48.1351, 11.5820),
    ("Frankfurt", "Germany", 50.1109, 8.6821),
    ("Hamburg", "Germany", 53.5511, 9.9937),
    ("Amsterdam", "Netherlands", 52.3676, 4.9041),
    ("Rotterdam", "Netherlands", 51.9244, 4.4777),
    ("Brussels", "Belgium", 50.8503, 4.3517),
    ("Vienna", "Austria", 48.2082, 16.3738),
    ("Zurich", "Switzerland", 47.3769, 8.5417),
    ("Geneva", "Switzerland", 46.2044, 6.1432),
    ("Rome", "Italy", 41.9028, 12.4964),
    ("Milan", "Italy", 45.4642, 9.1900),
    ("Madrid", "Spain", 40.4168, -3.7038),
    ("Barcelona", "Spain", 41.3879, 2.1699),
    ("Lisbon", "Portugal", 38.7223, -9.1393),
    ("Athens", "Greece", 37.9838, 23.7275),
    ("Warsaw", "Poland", 52.2297, 21.0122),
    ("Prague", "Czech Republic", 50.0755, 14.4378),
    ("Budapest", "Hungary", 47.4979, 19.0402),
    ("Bucharest", "Romania", 44.4268, 26.1025),
    ("Sofia", "Bulgaria", 42.6977, 23.3219),
    ("Kyiv", "Ukraine", 50.4501, 30.5234),
    ("Istanbul", "Turkey", 41.0082, 28.9784),
    ("Ankara", "Turkey", 39.9334, 32.8597),
    ("New York", "United States", 40.7128, -74.0060),
    ("Los Angeles", "United States", 34.0522, -118.2437),
    ("Chicago", "United States", 41.8781, -87.6298),
    ("Houston", "United States", 29.7604, -95.3698),
    ("Phoenix", "United States", 33.4484, -112.0740),
    ("Philadelphia", "United States", 39.9526, -75.1652),
    ("San Antonio", "United States", 29.4241, -98.4936),
    ("San Diego", "United States", 32.7157, -117.1611),
    ("Dallas", "United States", 32.7767, -96.7970),
    ("San Francisco", "United States", 37.7749, -122.4194),
    ("San Jose", "United States", 37.3382, -121.8863),
    ("Austin", "United States", 30.2672, -97.7431),
    ("Seattle", "United States", 47.6062, -122.3321),
    ("Denver", "United States", 39.7392, -104.9903),
    ("Washington", "United States", 38.9072, -77.0369),
    ("Boston", "United States", 42.3601, -71.0589),
    ("Miami", "United States", 25.7617, -80.1918),
    ("Atlanta", "United States", 33.7490, -84.3880),
    ("Toronto", "Canada", 43.6532, -79.3832),
    ("Montreal", "Canada", 45.5017, -73.5673),
    ("Vancouver", "Canada", 49.2827, -123.1207),
    ("Mexico City", "Mexico", 19.4326, -99.1332),
    ("São Paulo", "Brazil", -23.5505, -46.6333),
    ("Rio de Janeiro", "Brazil", -22.9068, -43.1729),
    ("Buenos Aires", "Argentina", -34.6037, -58.3816),
    ("Santiago", "Chile", -33.4489, -70.6693),
    ("Bogotá", "Colombia", 4.7110, -74.0721),
    ("Lima", "Peru", -12.0464, -77.0428),
    ("Tokyo", "Japan", 35.6762, 139.6503),
    ("Osaka", "Japan", 34.6937, 135.5023),
    ("Seoul", "South Korea", 37.5665, 126.9780),
    ("Beijing", "China", 39.9042, 116.4074),
    ("Shanghai", "China", 31.2304, 121.4737),
    ("Hong Kong", "China", 22.3193, 114.1694),
    ("Singapore", "Singapore", 1.3521, 103.8198),
    ("Bangkok", "Thailand", 13.7563, 100.5018),
    ("Kuala Lumpur", "Malaysia", 3.1390, 101.6869),
    ("Jakarta", "Indonesia", -6.2088, 106.8456),
    ("Manila", "Philippines", 14.5995, 120.9842),
    ("New Delhi", "India", 28.6139, 77.2090),
    ("Mumbai", "India", 19.0760, 72.8777),
    ("Bengaluru", "India", 12.9716, 77.5946),
    ("Sydney", "Australia", -33.8688, 151.2093),
    ("Melbourne", "Australia", -37.8136, 144.9631),
    ("Brisbane", "Australia", -27.4698, 153.0251),
    ("Auckland", "New Zealand", -36.8485, 174.7633),
    ("Wellington", "New Zealand", -41.2865, 174.7762),
    ("Cairo", "Egypt", 30.0444, 31.2357),
    ("Cape Town", "South Africa", -33.9249, 18.4241),
    ("Johannesburg", "South Africa", -26.2041, 28.0473),
    ("Nairobi", "Kenya", -1.2921, 36.8219),
    ("Dubai", "United Arab Emirates", 25.2048, 55.2708),
    ("Doha", "Qatar", 25.2854, 51.5310),
    ("Riyadh", "Saudi Arabia", 24.7136, 46.6753),
    ("Tel Aviv", "Israel", 32.0853, 34.7818),
]

def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great circle distance between two points on the earth in km."""
    r = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c

class GeoResolver:
    _instance = None
    _cache: Dict[Tuple[float, float], Dict[str, str]] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def _round_key(cls, lat: float, lon: float) -> Tuple[float, float]:
        # Round to 3 decimal places (~110m precision) for caching
        return (round(lat, 3), round(lon, 3))

    @classmethod
    def resolve_offline(cls, lat: float, lon: float) -> Dict[str, str]:
        """Find the closest city in the offline world cities table."""
        closest_city = "Unknown City"
        closest_country = "Unknown Country"
        min_dist = float('inf')

        for city, country, clat, clon in OFFLINE_CITIES:
            dist = haversine_distance_km(lat, lon, clat, clon)
            if dist < min_dist:
                min_dist = dist
                closest_city = city
                closest_country = country

        return {
            "city": closest_city,
            "country": closest_country,
            "display_name": f"{closest_city}, {closest_country}",
            "source": "offline_database",
            "distance_km": round(min_dist, 1),
            "latitude": lat,
            "longitude": lon
        }

    @classmethod
    def resolve_coordinates(cls, lat: float, lon: float) -> Dict[str, Any]:
        """
        Reverse geocode latitude and longitude to city, country.
        First checks in-memory cache, attempts Nominatim (if online), and falls back
        gracefully to offline nearest-neighbor dataset.
        """
        key = cls._round_key(lat, lon)
        if key in cls._cache:
            return cls._cache[key]

        # Check if external geolocation lookups are allowed by administrator policy
        from app.core.settings_store import settings_store
        if settings_store.is_external_allowed("allow_geolocation_lookups"):
            nominatim_url = f"https://nominatim.openstreetmap.org/reverse?lat={lat:.6f}&lon={lon:.6f}&format=json&accept-language=en"
            headers = {
                "User-Agent": "FileSanitizer-Location-Service/1.0 (Security Analysis Platform)"
            }

            try:
                with httpx.Client(timeout=2.5, follow_redirects=True) as client:
                    res = client.get(nominatim_url, headers=headers)
                    if res.status_code == 200:
                        data = res.json()
                        addr = data.get("address", {})

                        city = (
                            addr.get("city")
                            or addr.get("town")
                            or addr.get("village")
                            or addr.get("municipality")
                            or addr.get("county")
                            or addr.get("state")
                            or "Unknown City"
                        )
                        country = addr.get("country") or "Unknown Country"

                        result = {
                            "city": city,
                            "country": country,
                            "display_name": f"{city}, {country}",
                            "source": "openstreetmap_nominatim",
                            "latitude": lat,
                            "longitude": lon
                        }
                        cls._cache[key] = result
                        return result
            except Exception as e:
                logger.debug(f"Online reverse geocoding failed (using offline fallback): {e}")

        # Fallback to offline nearest-neighbor city lookup
        result = cls.resolve_offline(lat, lon)
        cls._cache[key] = result
        return result

    _ip_cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def resolve_ip(cls, ip: str) -> Dict[str, Any]:
        """Resolve public IPv4 address to Country, City, and ASN info."""
        import ipaddress
        if not ip:
            return {"ip": "", "country": "Unknown", "city": "Unknown", "asn": "Unknown", "is_private": True}
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                return {
                    "ip": ip,
                    "country": "Local/Private Network",
                    "city": "Internal",
                    "asn": "RFC 1918 Private Address",
                    "is_private": True
                }
        except Exception:
            return {"ip": ip, "country": "Invalid IP", "city": "", "asn": "", "is_private": True}

        if ip in cls._ip_cache:
            return cls._ip_cache[ip]

        # Check if external lookups allowed
        try:
            from app.core.settings_store import settings_store
            if settings_store.is_external_allowed("allow_geolocation_lookups"):
                with httpx.Client(timeout=3.0) as client:
                    resp = client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,as,org,isp")
                    if resp.status_code == 200:
                        d = resp.json()
                        if d.get("status") == "success":
                            res = {
                                "ip": ip,
                                "country": d.get("country", "Unknown"),
                                "city": d.get("city", "Unknown"),
                                "asn": d.get("as") or d.get("org") or d.get("isp", "Unknown"),
                                "is_private": False
                            }
                            cls._ip_cache[ip] = res
                            return res
        except Exception as e:
            logger.debug(f"IP Geolocation resolution failed for {ip}: {e}")

        # Fallback
        res = {
            "ip": ip,
            "country": "Public Host",
            "city": "Public",
            "asn": "Unknown ASN",
            "is_private": False
        }
        cls._ip_cache[ip] = res
        return res

geo_resolver = GeoResolver()
