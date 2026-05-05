import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  images: { unoptimized: true },
  // Don't strip trailing slashes off API URLs the dashboard sends.
  // See the ``redirect_slashes=False`` change on the FastAPI side
  // for the full root-cause story — together they kill the cross-
  // origin redirect chain that was dropping cookies.
  skipTrailingSlashRedirect: true,
  async redirects() {
    // /brand-defender was the standalone Brand Defender page; the
    // functionality now lives as a sub-tab under /brand. Redirect
    // any bookmarked URL — including deep-link variants with an
    // ?id= parameter — to the canonical place.
    return [
      {
        source: "/brand-defender",
        destination: "/brand?tab=defender",
        permanent: true,
      },
      {
        source: "/brand-defender/:path*",
        destination: "/brand?tab=defender",
        permanent: true,
      },
    ];
  },
  async rewrites() {
    return [
      // Trailing-slash variant — many FastAPI routes are declared
      // with an explicit ``/`` (e.g. ``GET /organizations/``) and
      // FastAPI's path matcher requires the slash to be present.
      // The default ``/api/:path*`` rule strips the slash via
      // path-pattern normalisation. This rule comes first to win
      // dispatch when the slash is present.
      {
        source: "/api/:path*/",
        destination: "http://localhost:8000/api/:path*/",
      },
      {
        source: "/api/:path*",
        destination: "http://localhost:8000/api/:path*",
      },
    ];
  },
};

export default nextConfig;
