#!/usr/bin/env node
import { main } from './index.js';
import { errorMessage } from '../utils/errors.js';
import { ExitCode } from '../utils/exit-codes.js';

main(process.argv).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`${errorMessage(error)}
`);
    process.exitCode = ExitCode.InternalError;
  },
);
