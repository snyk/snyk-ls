/*
 * © 2025 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import * as fs from "node:fs";
import crypto from 'crypto';

const content = fs.readFileSync("/Users/bdoetsch/workspace/php-goof/exploits/gotcha_font.php", { encoding: 'utf8' });
const hash = crypto.createHash("sha256").update(content).digest("hex")
console.log(hash)
