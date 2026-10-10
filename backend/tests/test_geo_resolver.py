import pytest
from app.network.geo_resolver import GeoResolver, haversine_distance_km

def test_haversine_distance():
    # Distance between Stockholm (59.3293, 18.0686) and Oslo (59.9139, 10.7522) is approx 417 km
    dist = haversine_distance_km(59.3293, 18.0686, 59.9139, 10.7522)
    assert 400 < dist < 450

def test_resolve_offline_stockholm():
    resolver = GeoResolver()
    res = resolver.resolve_offline(59.329167, 18.068611)
    assert res["city"] == "Stockholm"
    assert res["country"] == "Sweden"
    assert "Stockholm, Sweden" in res["display_name"]
    assert res["source"] == "offline_database"
    assert res["distance_km"] < 1.0

def test_resolve_offline_paris():
    resolver = GeoResolver()
    res = resolver.resolve_offline(48.8584, 2.2945) # Eiffel Tower
    assert res["city"] == "Paris"
    assert res["country"] == "France"

def test_resolve_offline_san_francisco():
    resolver = GeoResolver()
    res = resolver.resolve_offline(37.7749, -122.4194)
    assert res["city"] == "San Francisco"
    assert res["country"] == "United States"

def test_resolve_coordinates_caching():
    resolver = GeoResolver()
    # First call
    res1 = resolver.resolve_coordinates(59.329167, 18.068611)
    # Second call should hit cache
    res2 = resolver.resolve_coordinates(59.329167, 18.068611)
    assert res1 == res2
    assert "Stockholm" in res1["city"]
    assert "Sweden" in res1["country"]
