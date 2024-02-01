#!/usr/bin/env python3
"""
Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The OpenAirInterface Software Alliance licenses this file to You under
the OAI Public License, Version 1.1  (the "License"); you may not use this file
except in compliance with the License.
You may obtain a copy of the License at

  http://www.openairinterface.org/?page_id=698

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
------------------------------------------------------------------------------
For more information about the OpenAirInterface (OAI) Software Alliance:
  contact@openairinterface.org
---------------------------------------------------------------------
"""

#import argparse
import os
import re

from common.python.pipeline_args_parse import (
    _parse_args,
)

from common.python.generate_html import (
    generate_header,
    generate_footer,
    generate_git_info,
)

from common.python.code_format_checker import (
    coding_formatting_log_check,
)

from common.python.static_code_analysis import (
    analyze_sca_log_check,
)

from common.python.building_report import (
    build_summary,
)

REPORT_NAME = 'test_results_oai_upf.html'

class HtmlReport():
    def __init__(self):
        pass

    def generate(self, args):
        cwd = os.getcwd()
        with open(os.path.join(cwd, REPORT_NAME), 'w') as wfile:
            wfile.write(generate_header(args))
            wfile.write(generate_git_info(args))
            wfile.write(build_summary(args, 'upf', '22', '9'))
            wfile.write(coding_formatting_log_check(args))
            wfile.write(analyze_sca_log_check())
            wfile.write(generate_footer())

    def appendToTestReports(self, args):
        gitInfo = generate_git_info(args)
        cwd = os.getcwd()
        for reportFile in os.listdir(cwd):
            if reportFile.endswith('.html') and (re.search('results_oai_cn5g_', reportFile) is not None or re.search('test_results_robot_', reportFile) is not None):
                newFile = ''
                robotBuildUrl = ''
                gitInfoAppended = False
                with open(os.path.join(cwd, reportFile), 'r') as rfile:
                    for line in rfile:
                        if re.search('<h2>', line) is not None and not gitInfoAppended:
                            gitInfoAppended = True
                            newFile += gitInfo
                        if re.search('OAI-CN5G-RobotTest -- Build-ID', line) is not None:
                            result = re.search('href="(?P<build_url>[a-zA-Z0-9\-\:\/\.]+)"', line)
                            if result is not None:
                                robotBuildUrl = result.group('build_url')
                        if re.search('archives/log.html', line) is not None:
                            newFile += re.sub('archives', f'{robotBuildUrl}/artifact/archives', line)
                        else:
                            newFile += line
                with open(os.path.join(cwd, reportFile), 'w') as wfile:
                    wfile.write(newFile)

if __name__ == '__main__':
    # Parse the arguments
    args = _parse_args()

    # Generate report
    HTML = HtmlReport()
    HTML.generate(args)
    HTML.appendToTestReports(args)
