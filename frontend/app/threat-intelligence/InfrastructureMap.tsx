"use client";

import { useEffect } from "react";
import { CircleMarker, MapContainer, Popup, TileLayer, useMap } from "react-leaflet";
import type { LatLngBoundsExpression } from "leaflet";

export type InfrastructurePoint = {
  ip: string;
  latitude: number;
  longitude: number;
  country?: string | null;
  city?: string | null;
  provider?: string | null;
  asn?: string | number | null;
  earliest?: boolean;
};

function FitBounds({ points }: { points: InfrastructurePoint[] }) {
  const map = useMap();
  useEffect(() => {
    if (points.length > 1) {
      const bounds: LatLngBoundsExpression = points.map((point) => [point.latitude, point.longitude]);
      map.fitBounds(bounds, { padding: [24, 24] });
    } else if (points[0]) {
      map.setView([points[0].latitude, points[0].longitude], 4);
    }
  }, [map, points]);
  return null;
}

export default function InfrastructureMap({ points }: { points: InfrastructurePoint[] }) {
  if (!points.length) return null;
  return (
    <MapContainer center={[points[0].latitude, points[0].longitude]} zoom={3} scrollWheelZoom className="h-[320px] w-full rounded-xl">
      <TileLayer attribution='&copy; OpenStreetMap contributors' url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
      <FitBounds points={points} />
      {points.map((point) => (
        <CircleMarker key={`${point.ip}-${point.latitude}-${point.longitude}`} center={[point.latitude, point.longitude]} radius={point.earliest ? 10 : 7} pathOptions={{ color: point.earliest ? "#fbbf24" : "#22d3ee", fillColor: point.earliest ? "#f59e0b" : "#06b6d4", fillOpacity: 0.85 }}>
          <Popup>
            <strong>{point.earliest ? "Earliest Visible Infrastructure" : "Infrastructure Location"}</strong><br />
            IP: {point.ip}<br />
            Country: {point.country || "Unavailable"}<br />
            City: {point.city || "Unavailable"}<br />
            Provider: {point.provider || "Unavailable"}<br />
            ASN: {point.asn || "Unavailable"}
          </Popup>
        </CircleMarker>
      ))}
    </MapContainer>
  );
}
