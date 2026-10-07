/* Cross-module wiring. app.js fills in the functions at boot so views can
   reach shared behavior (open a drawer, navigate, refresh) without
   importing each other in a cycle. */

export const ctx = {
  cases: [], // light case list from the latest dashboard payload
  status: null, // GET /api/status, loaded once at boot
  activeTable: null, // the AlertTable on screen (keyboard, palette, bulk bar)
  openAlert: async () => {},
  openHost: async () => {},
  bulkVerdict: async () => {},
  setVerdict: async () => {},
  navigate: () => {},
  sync: async () => {},
};
