#!/usr/bin/env python3
# Copyright 2024 brian <gao.brian@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from pathlib import Path
import subprocess

if __name__ == "__main__":
    basedir = Path(__file__).parent.parent

    output = basedir / "target"
    Path(output).mkdir(exist_ok=True, parents=True)
    cmd = ["cargo", "build", "--target-dir", str(output)]
    print("$ " + subprocess.list2cmdline(cmd))
    subprocess.run(cmd, cwd=basedir, check=True)