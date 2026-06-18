// ESM entry point for @nais-standard/sdk.
// The implementation lives in the CommonJS index.js; this wrapper re-exports it
// as named ESM bindings so `import { resolve } from '@nais-standard/sdk'` works, while
// `require('@nais-standard/sdk')` continues to resolve to index.js.

import sdk from './index.js';

export const {
  resolve,
  validate,
  verifyCard,
  canonicalize,
  parseNaisTxt,
  normalizeDomain,
  NaisResolutionError,
} = sdk;

export default sdk;
