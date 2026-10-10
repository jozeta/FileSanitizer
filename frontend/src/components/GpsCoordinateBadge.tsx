import React, { useState, useEffect, useRef } from 'react';
import { MapPin, ExternalLink, Globe, Navigation, Compass, Loader2 } from 'lucide-react';

interface GpsCoordinateBadgeProps {
  latitude?: number | string | null;
  longitude?: number | string | null;
  readableCoordinates?: string;
  initialCity?: string;
  initialCountry?: string;
  locationName?: string;
  className?: string;
}

// Coordinate parsing helper
function parseCoordinates(
  latProp?: number | string | null,
  lonProp?: number | string | null,
  text?: string
): { lat: number | null; lon: number | null } {
  if (latProp !== undefined && latProp !== null && lonProp !== undefined && lonProp !== null) {
    const lat = typeof latProp === 'number' ? latProp : parseFloat(String(latProp).trim());
    const lon = typeof lonProp === 'number' ? lonProp : parseFloat(String(lonProp).trim());
    if (!isNaN(lat) && !isNaN(lon)) return { lat, lon };
  }

  if (text) {
    const match = text.match(/([+-]?\d+(?:\.\d+)?)[,\s]+([+-]?\d+(?:\.\d+)?)/);
    if (match) {
      const lat = parseFloat(match[1]);
      const lon = parseFloat(match[2]);
      if (!isNaN(lat) && !isNaN(lon)) return { lat, lon };
    }
  }

  return { lat: null, lon: null };
}

export const GpsCoordinateBadge: React.FC<GpsCoordinateBadgeProps> = ({
  latitude,
  longitude,
  readableCoordinates,
  initialCity,
  initialCountry,
  locationName,
  className = '',
}) => {
  const { lat, lon } = parseCoordinates(latitude, longitude, readableCoordinates);
  const [city, setCity] = useState<string>(initialCity || '');
  const [country, setCountry] = useState<string>(initialCountry || '');
  const [resolvedDisplay, setResolvedDisplay] = useState<string>(locationName || '');
  const [isOpen, setIsOpen] = useState(false);
  const [coordsPos, setCoordsPos] = useState<{ x: number; y: number } | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const triggerRef = useRef<HTMLDivElement | null>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Sync props if they update
  useEffect(() => {
    if (initialCity) setCity(initialCity);
    if (initialCountry) setCountry(initialCountry);
    if (locationName) setResolvedDisplay(locationName);
  }, [initialCity, initialCountry, locationName]);

  const handleMouseEnter = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);

    if (triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      const popoverWidth = 320;
      const popoverHeight = 220;

      // Position above if space allows, otherwise below
      const fitsAbove = rect.top > popoverHeight + 15;
      const x = Math.max(16, Math.min(rect.left, window.innerWidth - popoverWidth - 16));
      const y = fitsAbove ? rect.top - popoverHeight - 8 : rect.bottom + 8;

      setCoordsPos({ x, y });
    }

    setIsOpen(true);

    // Fetch reverse geocode if not already known
    if ((!city || city === 'Unknown City') && lat !== null && lon !== null && !isLoading) {
      setIsLoading(true);
      fetch(`/api/files/reverse-geocode?lat=${lat}&lon=${lon}`)
        .then((res) => {
          if (!res.ok) throw new Error('Failed to resolve coordinates');
          return res.json();
        })
        .then((data: { city?: string; country?: string; display_name?: string }) => {
          if (data) {
            if (data.city && data.city !== 'Unknown City') {
              setCity(data.city);
            }
            if (data.country && data.country !== 'Unknown Country') {
              setCountry(data.country);
            }
            if (data.display_name) {
              setResolvedDisplay(data.display_name);
            }
          }
        })
        .catch(() => {})
        .finally(() => {
          setIsLoading(false);
        });
    }
  };

  const handleMouseLeave = () => {
    timeoutRef.current = setTimeout(() => {
      setIsOpen(false);
    }, 280);
  };

  const handlePopoverMouseEnter = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
  };

  if (lat === null || lon === null) {
    return <span>{readableCoordinates || 'GPS Coordinates'}</span>;
  }

  const displayText = readableCoordinates || `${lat.toFixed(6)}, ${lon.toFixed(6)}`;
  const latFormatted = `${Math.abs(lat).toFixed(4)}° ${lat >= 0 ? 'N' : 'S'}`;
  const lonFormatted = `${Math.abs(lon).toFixed(4)}° ${lon >= 0 ? 'E' : 'W'}`;

  const resolvedTitle =
    city && country && city !== 'Unknown City'
      ? `${city}, ${country}`
      : resolvedDisplay || 'Locating region...';

  const osmUrl = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=15/${lat}/${lon}`;
  const googleMapsUrl = `https://www.google.com/maps?q=${lat},${lon}`;

  return (
    <div
      ref={triggerRef}
      className={`relative inline-block ${className}`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      {/* Interactive Trigger Badge */}
      <div
        className={`group inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border transition-all cursor-pointer select-none ${
          isOpen
            ? 'bg-blue-600 text-white border-blue-600 shadow-md ring-2 ring-blue-300'
            : 'bg-blue-50/80 hover:bg-blue-100 text-blue-800 border-blue-200/80 hover:border-blue-300 shadow-xs'
        }`}
      >
        <MapPin
          className={`w-3.5 h-3.5 shrink-0 transition-transform ${
            isOpen ? 'text-white scale-110' : 'text-blue-600 group-hover:scale-110'
          }`}
        />
        <span className="font-mono text-xs font-semibold tracking-tight">{displayText}</span>
        {city && city !== 'Unknown City' && (
          <span
            className={`text-[11px] font-sans px-1.5 py-0.2 rounded font-medium ${
              isOpen ? 'bg-blue-700 text-blue-100' : 'bg-blue-100/80 text-blue-700'
            }`}
          >
            {city}
          </span>
        )}
      </div>

      {/* Fixed High Z-Index Hover Card that is never hidden under sticky menus */}
      {isOpen && coordsPos && (
        <div
          onMouseEnter={handlePopoverMouseEnter}
          onMouseLeave={handleMouseLeave}
          style={{
            position: 'fixed',
            left: coordsPos.x,
            top: coordsPos.y,
            zIndex: 9999,
          }}
          className="w-72 sm:w-80 p-4 bg-white rounded-2xl shadow-2xl border border-slate-200 text-slate-800 text-left animate-modal-fade pointer-events-auto"
        >
          {/* Header with compass icon */}
          <div className="flex items-center justify-between pb-2 mb-2.5 border-b border-slate-100">
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">
              <Compass className="w-3.5 h-3.5 text-blue-600" />
              <span>Geolocation Identified</span>
            </div>
            {isLoading && (
              <span className="flex items-center gap-1 text-[11px] text-blue-600 font-mono">
                <Loader2 className="w-3 h-3 animate-spin" />
                Resolving...
              </span>
            )}
          </div>

          {/* City, Country Highlight */}
          <div className="mb-3">
            <div className="flex items-start gap-2">
              <div className="p-2 rounded-xl bg-blue-50 text-blue-600 shrink-0 mt-0.5">
                <Navigation className="w-4 h-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-bold text-slate-900 leading-snug break-words">
                  {resolvedTitle}
                </div>
                <div className="text-xs text-slate-500 font-mono mt-0.5">
                  {latFormatted} · {lonFormatted}
                </div>
              </div>
            </div>
          </div>

          {/* Coordinate Details Box */}
          <div className="bg-slate-50 rounded-xl p-2.5 mb-3 border border-slate-100 font-mono text-[11px] space-y-1">
            <div className="flex justify-between text-slate-600">
              <span className="text-slate-400">Latitude:</span>
              <span className="font-semibold text-slate-800">{lat.toFixed(6)}</span>
            </div>
            <div className="flex justify-between text-slate-600">
              <span className="text-slate-400">Longitude:</span>
              <span className="font-semibold text-slate-800">{lon.toFixed(6)}</span>
            </div>
          </div>

          {/* External Map Quick-Links */}
          <div className="flex items-center gap-2 pt-1 border-t border-slate-100">
            <a
              href={osmUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 inline-flex items-center justify-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium transition-colors"
            >
              <Globe className="w-3 h-3 text-slate-500" />
              <span>OpenStreetMap</span>
              <ExternalLink className="w-2.5 h-2.5 text-slate-400" />
            </a>
            <a
              href={googleMapsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 inline-flex items-center justify-center gap-1 px-2.5 py-1.5 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-700 text-xs font-medium transition-colors"
            >
              <MapPin className="w-3 h-3 text-blue-600" />
              <span>Google Maps</span>
              <ExternalLink className="w-2.5 h-2.5 text-blue-400" />
            </a>
          </div>
        </div>
      )}
    </div>
  );
};
