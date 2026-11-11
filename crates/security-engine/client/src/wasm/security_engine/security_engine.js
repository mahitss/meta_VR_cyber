/* @ts-self-types="./security_engine.d.ts" */
import * as wasm from "./security_engine_bg.wasm";
import { __wbg_set_wasm } from "./security_engine_bg.js";

__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    health_check_json, simulate_graph_json
} from "./security_engine_bg.js";
export { wasm as __wasm }
