"use client";

import { useState, useCallback } from "react";
import MapGL from "react-map-gl/maplibre";
import "maplibre-gl/dist/maplibre-gl.css";

const MAP_STYLE =
  "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json";

export function WorldMap() {
  const [viewState, setViewState] = useState({
    longitude: 15,
    latitude: 25,
    zoom: 2.2,
    pitch: 0,
    bearing: 0,
  });

  const onMove = useCallback(
    (evt: { viewState: typeof viewState }) => setViewState(evt.viewState),
    []
  );

  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
        filter: "blur(1.5px)",
        pointerEvents: "none",
      }}
    >
      <MapGL
        {...viewState}
        onMove={onMove}
        mapStyle={MAP_STYLE}
        style={{ width: "100%", height: "100%" }}
        interactive={false}
        attributionControl={false}
      />
    </div>
  );
}
