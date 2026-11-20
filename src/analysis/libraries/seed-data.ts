// Bundled seed vulnerability data in the retire.js repository format (jsrepository.json).
// Source: https://github.com/RetireJS/retire.js (repository/jsrepository.json), Apache-2.0 licensed,
// Copyright the retire.js authors. This is a small, verbatim subset (extractors and advisories were
// copied from the upstream file and cross-checked entry by entry; the in-code "func" and
// "filecontentreplace" extractors, which need a browser or are not supported here, were dropped).
// It is a fallback only: run "thirdsentry vulndb update" for the complete, current database.
// Advisories included: 37.
export const SEED_SOURCE_DATE = '2026-11-20';
export const SEED_DB_JSON: unknown = {
  "jquery": {
    "vulnerabilities": [
      {
        "below": "1.6.3",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS with location.hash",
          "CVE": [
            "CVE-2011-4969"
          ]
        },
        "info": [
          "https://bugs.jquery.com/ticket/9521",
          "https://nvd.nist.gov/vuln/detail/CVE-2011-4969"
        ]
      },
      {
        "below": "1.9.0b1",
        "severity": "medium",
        "identifiers": {
          "summary": "Selector interpreted as HTML",
          "CVE": [
            "CVE-2012-6708"
          ]
        },
        "info": [
          "https://nvd.nist.gov/vuln/detail/CVE-2012-6708"
        ]
      },
      {
        "atOrAbove": "1.4.0",
        "below": "1.12.0",
        "severity": "medium",
        "identifiers": {
          "summary": "3rd party CORS request may execute",
          "CVE": [
            "CVE-2015-9251"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-rmxg-73gg-4p98",
          "https://github.com/jquery/jquery/issues/2432",
          "https://nvd.nist.gov/vuln/detail/CVE-2015-9251"
        ]
      },
      {
        "atOrAbove": "1.12.3",
        "below": "3.0.0-beta1",
        "severity": "medium",
        "identifiers": {
          "summary": "3rd party CORS request may execute",
          "CVE": [
            "CVE-2015-9251"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-rmxg-73gg-4p98",
          "https://github.com/jquery/jquery/issues/2432",
          "https://nvd.nist.gov/vuln/detail/CVE-2015-9251"
        ]
      },
      {
        "atOrAbove": "1.1.4",
        "below": "3.4.0",
        "severity": "medium",
        "identifiers": {
          "summary": "jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution",
          "CVE": [
            "CVE-2019-11358"
          ]
        },
        "info": [
          "https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/",
          "https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-11358"
        ]
      },
      {
        "atOrAbove": "1.0.3",
        "below": "3.5.0",
        "severity": "medium",
        "identifiers": {
          "summary": "passing HTML containing <option> elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted co",
          "CVE": [
            "CVE-2020-11023"
          ]
        },
        "info": [
          "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"
        ]
      },
      {
        "atOrAbove": "1.12.0",
        "below": "3.5.0",
        "severity": "medium",
        "identifiers": {
          "summary": "Regex in its jQuery.htmlPrefilter sometimes may introduce XSS",
          "CVE": [
            "CVE-2020-11022"
          ]
        },
        "info": [
          "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"
        ]
      }
    ],
    "extractors": {
      "uri": [
        "/(§§version§§)/jquery(\\.min)?\\.js"
      ],
      "filename": [
        "jquery-(§§version§§)(\\.min)?\\.js"
      ],
      "filecontent": [
        "/\\*!? jQuery v(§§version§§)",
        "\\* jQuery JavaScript Library v(§§version§§)",
        "\\* jQuery (§§version§§) - New Wave Javascript",
        "/\\*![\\s]+\\* jQuery JavaScript Library v(§§version§§)",
        "// \\$Id: jquery.js,v (§§version§§)",
        "/\\*! jQuery v(§§version§§)",
        "[^a-z]f=\"(§§version§§)\",.*[^a-z]jquery:f,",
        "[^a-z]m=\"(§§version§§)\",.*[^a-z]jquery:m,",
        "[^a-z.]jquery:[ ]?\"(§§version§§)\"",
        "\\$\\.documentElement,Q=e.jQuery,Z=e\\.\\$,ee=\\{\\},te=\\[\\],ne=\"(§§version§§)\"",
        "=\"(§§version§§)\",.{50,300}(.)\\.fn=(\\2)\\.prototype=\\{jquery:"
      ]
    }
  },
  "jquery-ui": {
    "vulnerabilities": [
      {
        "below": "1.13.0",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS in the `altField` option of the Datepicker widget",
          "CVE": [
            "CVE-2021-41182"
          ]
        },
        "info": [
          "https://github.com/jquery/jquery-ui/security/advisories/GHSA-9gj3-hwp5-pmwc",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-41182"
        ]
      },
      {
        "below": "1.13.0",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS in the `of` option of the `.position()` util",
          "CVE": [
            "CVE-2021-41184"
          ]
        },
        "info": [
          "https://github.com/jquery/jquery-ui/security/advisories/GHSA-gpqq-952q-5327",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-41184"
        ]
      },
      {
        "below": "1.13.0",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS Vulnerability on text options of jQuery UI datepicker",
          "CVE": [
            "CVE-2021-41183"
          ]
        },
        "info": [
          "https://bugs.jqueryui.com/ticket/15284",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-41183"
        ]
      },
      {
        "below": "1.13.2",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS when refreshing a checkboxradio with an HTML-like initial text label ",
          "CVE": [
            "CVE-2022-31160"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-h6gj-6jjq-h8g9",
          "https://github.com/jquery/jquery-ui/commit/8cc5bae1caa1fcf96bf5862c5646c787020ba3f9",
          "https://github.com/jquery/jquery-ui/issues/2101"
        ]
      }
    ],
    "extractors": {
      "uri": [
        "/(§§version§§)/jquery-ui(\\.min)?\\.js"
      ],
      "filecontent": [
        "/\\*!? jQuery UI - v(§§version§§)",
        "/\\*!?[\n *]+jQuery UI (§§version§§)"
      ]
    }
  },
  "bootstrap": {
    "vulnerabilities": [
      {
        "atOrAbove": "2.3.0",
        "below": "3.4.0",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS in collapse data-parent attribute",
          "CVE": [
            "CVE-2018-14040"
          ]
        },
        "info": [
          "https://github.com/twbs/bootstrap/issues/20184"
        ]
      },
      {
        "atOrAbove": "2.3.0",
        "below": "3.4.0",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS in data-container property of tooltip",
          "CVE": [
            "CVE-2018-14042"
          ]
        },
        "info": [
          "https://github.com/twbs/bootstrap/issues/20184"
        ]
      },
      {
        "atOrAbove": "3.0.0",
        "below": "3.4.1",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS in data-template, data-content and data-title properties of tooltip/popover",
          "CVE": [
            "CVE-2019-8331"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-9v3m-8fp8-mj99",
          "https://github.com/twbs/bootstrap/issues/28236"
        ]
      },
      {
        "atOrAbove": "4.0.0",
        "below": "4.1.2",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS in collapse data-parent attribute",
          "CVE": [
            "CVE-2018-14040"
          ]
        },
        "info": [
          "https://github.com/twbs/bootstrap/issues/20184"
        ]
      },
      {
        "atOrAbove": "4.0.0",
        "below": "4.1.2",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS in data-container property of tooltip",
          "CVE": [
            "CVE-2018-14042"
          ]
        },
        "info": [
          "https://github.com/twbs/bootstrap/issues/20184"
        ]
      },
      {
        "atOrAbove": "4.0.0",
        "below": "4.1.2",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS in data-target property of scrollspy",
          "CVE": [
            "CVE-2018-14041"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-pj7m-g53m-7638",
          "https://github.com/twbs/bootstrap/issues/20184"
        ]
      },
      {
        "atOrAbove": "4.0.0",
        "below": "4.3.1",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS in data-template, data-content and data-title properties of tooltip/popover",
          "CVE": [
            "CVE-2019-8331"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-9v3m-8fp8-mj99",
          "https://github.com/twbs/bootstrap/issues/28236"
        ]
      }
    ],
    "extractors": {
      "uri": [
        "/(§§version§§)/bootstrap(\\.min)?\\.js",
        "/(§§version§§)/js/bootstrap(\\.min)?\\.js"
      ],
      "filename": [
        "bootstrap-(§§version§§)(\\.min)?\\.js"
      ],
      "filecontent": [
        "/\\*!? Bootstrap v(§§version§§)",
        "\\* Bootstrap v(§§version§§)",
        "/\\*! Bootstrap v(§§version§§)",
        "this\\.close\\)\\};.\\.VERSION=\"(§§version§§)\"(?:,.\\.TRANSITION_DURATION=150)?,.\\.prototype\\.close"
      ]
    }
  },
  "lodash": {
    "vulnerabilities": [
      {
        "below": "4.17.5",
        "severity": "medium",
        "identifiers": {
          "summary": "Prototype Pollution in lodash",
          "CVE": [
            "CVE-2018-3721"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
          "https://nvd.nist.gov/vuln/detail/CVE-2018-3721",
          "https://github.com/lodash/lodash/commit/d8e069cc3410082e44eb18fcf8e7f3d08ebe1d4a"
        ]
      },
      {
        "below": "4.17.12",
        "severity": "high",
        "identifiers": {
          "summary": "Prototype Pollution in lodash",
          "CVE": [
            "CVE-2019-10744"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-jf85-cpcp-j695",
          "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
          "https://github.com/lodash/lodash/pull/4336"
        ]
      },
      {
        "atOrAbove": "3.7.0",
        "below": "4.17.19",
        "severity": "high",
        "identifiers": {
          "summary": "Prototype Pollution in lodash",
          "CVE": [
            "CVE-2020-8203"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-p6mc-m468-83gw",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
          "https://github.com/lodash/lodash/issues/4744"
        ]
      },
      {
        "below": "4.17.21",
        "severity": "high",
        "identifiers": {
          "summary": "Command Injection in lodash",
          "CVE": [
            "CVE-2021-23337"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
          "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
          "https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c"
        ]
      }
    ],
    "extractors": {
      "filecontent": [
        "/\\*[\\s*!]+(?:@license)?[\\s*]+(?:Lo-Dash|lodash|Lodash) v?(§§version§§)[\\s\\S]{1,200}Build: `lodash modern -o",
        "/\\*[\\s*!]+(?:@license)?[\\s*]+(?:Lo-Dash|lodash|Lodash) v?(§§version§§) <",
        "/\\*[\\s*!]+(?:@license)?[\\s*]+(?:Lo-Dash|lodash|Lodash) v?(§§version§§) lodash.com/license",
        "=\"(§§version§§)(?<=[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2})\"[\\s\\S]{1,300}__lodash_hash_undefined__",
        "/\\*[\\s*]+@license[\\s*]+(?:Lo-Dash|lodhash|Lodash)[\\s\\S]{1,500}var VERSION *= *['\"](§§version§§)['\"]",
        "var VERSION=\"(§§version§§)\";var BIND_FLAG=1,BIND_KEY_FLAG=2,CURRY_BOUND_FLAG=4,CURRY_FLAG=8"
      ],
      "uri": [
        "/(§§version§§)/lodash(\\.min)?\\.js"
      ]
    }
  },
  "moment.js": {
    "vulnerabilities": [
      {
        "below": "2.11.2",
        "severity": "medium",
        "identifiers": {
          "summary": "reDOS - regular expression denial of service",
          "CVE": [
            "CVE-2016-4055"
          ]
        },
        "info": [
          "https://github.com/moment/moment/issues/2936"
        ]
      },
      {
        "below": "2.19.3",
        "severity": "high",
        "identifiers": {
          "summary": "Regular Expression Denial of Service (ReDoS)",
          "CVE": [
            "CVE-2017-18214"
          ]
        },
        "info": [
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18214",
          "https://github.com/moment/moment/issues/4163",
          "https://security.snyk.io/vuln/npm:moment:20170905"
        ]
      },
      {
        "below": "2.29.2",
        "severity": "high",
        "identifiers": {
          "summary": "This vulnerability impacts npm (server) users of moment.js, especially if user provided locale string, eg fr is directly used to switch moment locale.",
          "CVE": [
            "CVE-2022-24785"
          ]
        },
        "info": [
          "https://github.com/moment/moment/security/advisories/GHSA-8hfj-j24r-96c4"
        ]
      },
      {
        "atOrAbove": "2.18.0",
        "below": "2.29.4",
        "severity": "high",
        "identifiers": {
          "summary": "Regular Expression Denial of Service (ReDoS), Affecting moment package, versions >=2.18.0 <2.29.4",
          "CVE": [
            "CVE-2022-31129"
          ]
        },
        "info": [
          "https://github.com/moment/moment/security/advisories/GHSA-wc69-rhjr-hc9g",
          "https://security.snyk.io/vuln/SNYK-JS-MOMENT-2944238"
        ]
      }
    ],
    "extractors": {
      "uri": [
        "/moment\\.js/(§§version§§)/moment(.min)?\\.js"
      ],
      "filename": [
        "moment(?:-|\\.)(§§version§§)(?:-min)?\\.js"
      ],
      "filecontent": [
        "//!? moment.js(?:[\n\r]+)//!? version : (§§version§§)",
        "/\\* Moment.js +\\| +version : (§§version§§) \\|",
        "\\.version=\"(§§version§§)\".{20,60}\"isBefore\".{20,60}\"isAfter\".{200,500}\\.isMoment=",
        "\\.version=\"(§§version§§)\".{20,300}duration.{2,100}\\.isMoment=",
        "\\.isMoment\\(.{50,400}_isUTC.{50,400}=\"(§§version§§)\"",
        "=\"(§§version§§)\".{300,1000}Years:31536e6.{60,80}\\.isMoment",
        "// Moment.js is freely distributable under the terms of the MIT license.[\\s]+//[\\s]+// Version (§§version§§)"
      ]
    }
  },
  "angularjs": {
    "vulnerabilities": [
      {
        "below": "1.7.9",
        "severity": "high",
        "identifiers": {
          "summary": "Prototype pollution",
          "CVE": [
            "CVE-2019-10768"
          ]
        },
        "info": [
          "https://github.com/angular/angular.js/blob/master/CHANGELOG.md#179-pollution-eradication-2019-11-19",
          "https://github.com/angular/angular.js/commit/726f49dcf6c23106ddaf5cfd5e2e592841db743a"
        ]
      },
      {
        "below": "1.8.0",
        "severity": "medium",
        "identifiers": {
          "summary": "XSS may be triggered in AngularJS applications that sanitize user-controlled HTML snippets before passing them to JQLite methods like JQLite.prepend, JQLite.after, JQLite.append, JQLite.replaceWith, J",
          "CVE": [
            "CVE-2020-7676"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-5cp4-xmrw-59wf",
          "https://nvd.nist.gov/vuln/detail/CVE-2020-7676"
        ]
      }
    ],
    "extractors": {
      "uri": [
        "/(§§version§§)/angular(\\.min)?\\.js"
      ],
      "filename": [
        "angular(?:js)?-(§§version§§)(.min)?\\.js"
      ],
      "filecontent": [
        "/\\*[\\*\\s]+(?:@license )?AngularJS(?: NES)? v(§§version§§)",
        "http://errors\\.angularjs\\.org/(§§version§§)/"
      ]
    }
  },
  "handlebars": {
    "vulnerabilities": [
      {
        "below": "3.0.8",
        "severity": "high",
        "identifiers": {
          "summary": "Disallow calling helperMissing and blockHelperMissing directly",
          "CVE": [
            "CVE-2019-19919"
          ]
        },
        "info": [
          "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v430---september-24th-2019"
        ]
      },
      {
        "atOrAbove": "4.0.0",
        "below": "4.3.0",
        "severity": "high",
        "identifiers": {
          "summary": "Disallow calling helperMissing and blockHelperMissing directly",
          "CVE": [
            "CVE-2019-19919"
          ]
        },
        "info": [
          "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v430---september-24th-2019"
        ]
      },
      {
        "below": "4.7.7",
        "severity": "high",
        "identifiers": {
          "summary": "Prototype Pollution in handlebars",
          "CVE": [
            "CVE-2021-23383"
          ]
        },
        "info": [
          "https://nvd.nist.gov/vuln/detail/CVE-2021-23383"
        ]
      },
      {
        "below": "4.7.7",
        "severity": "high",
        "identifiers": {
          "summary": "Remote code execution in handlebars when compiling templates",
          "CVE": [
            "CVE-2021-23369"
          ]
        },
        "info": [
          "https://nvd.nist.gov/vuln/detail/CVE-2021-23369"
        ]
      }
    ],
    "extractors": {
      "uri": [
        "/(§§version§§)/handlebars(\\.min)?\\.js"
      ],
      "filename": [
        "handlebars(?:js)?-(§§version§§)(.min)?\\.js"
      ],
      "filecontent": [
        "Handlebars.VERSION = \"(§§version§§)\";",
        "Handlebars=\\{VERSION:(?:'|\")(§§version§§)(?:'|\")",
        "this.Handlebars=\\{\\};[\n\r \t]+\\(function\\([a-z]\\)\\{[a-z].VERSION=(?:'|\")(§§version§§)(?:'|\")",
        "exports.HandlebarsEnvironment=[\\s\\S]{70,120}exports.VERSION=(?:'|\")(§§version§§)(?:'|\")",
        "/\\*+![\\s]+(?:@license)?[\\s]+handlebars v+(§§version§§)",
        "window\\.Handlebars=.,.\\.VERSION=\"(§§version§§)\"",
        ".\\.HandlebarsEnvironment=.;var .=.\\(.\\),.=.\\(.\\),.=\"(§§version§§)\";.\\.VERSION="
      ]
    }
  },
  "DOMPurify": {
    "vulnerabilities": [
      {
        "below": "2.0.17",
        "severity": "medium",
        "identifiers": {
          "summary": "Fixed another bypass causing mXSS by using MathML",
          "CVE": [
            "CVE-2020-26870"
          ]
        },
        "info": [
          "https://github.com/cure53/DOMPurify/releases"
        ]
      },
      {
        "atOrAbove": "0",
        "below": "2.5.0",
        "severity": "high",
        "identifiers": {
          "summary": "DOMpurify has a nesting-based mXSS",
          "CVE": [
            "CVE-2024-47875"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-gx9m-whjm-85jf",
          "https://github.com/cure53/DOMPurify/security/advisories/GHSA-gx9m-whjm-85jf",
          "https://nvd.nist.gov/vuln/detail/CVE-2024-47875"
        ]
      },
      {
        "atOrAbove": "0",
        "below": "2.5.4",
        "severity": "high",
        "identifiers": {
          "summary": "DOMPurify allows tampering by prototype pollution",
          "CVE": [
            "CVE-2024-45801"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-mmhx-hmjr-r674",
          "https://github.com/cure53/DOMPurify/security/advisories/GHSA-mmhx-hmjr-r674",
          "https://nvd.nist.gov/vuln/detail/CVE-2024-45801"
        ]
      },
      {
        "atOrAbove": "3.0.0",
        "below": "3.1.3",
        "severity": "high",
        "identifiers": {
          "summary": "DOMpurify has a nesting-based mXSS",
          "CVE": [
            "CVE-2024-47875"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-gx9m-whjm-85jf",
          "https://github.com/cure53/DOMPurify/security/advisories/GHSA-gx9m-whjm-85jf",
          "https://nvd.nist.gov/vuln/detail/CVE-2024-47875"
        ]
      },
      {
        "atOrAbove": "3.0.0",
        "below": "3.1.3",
        "severity": "high",
        "identifiers": {
          "summary": "DOMPurify allows tampering by prototype pollution",
          "CVE": [
            "CVE-2024-45801"
          ]
        },
        "info": [
          "https://github.com/advisories/GHSA-mmhx-hmjr-r674",
          "https://github.com/cure53/DOMPurify/security/advisories/GHSA-mmhx-hmjr-r674",
          "https://nvd.nist.gov/vuln/detail/CVE-2024-45801"
        ]
      }
    ],
    "extractors": {
      "filecontent": [
        "DOMPurify.version = '(§§version§§)';",
        "DOMPurify.version=\"(§§version§§)\"",
        "DOMPurify=.[^\\r\\n]{10,850}?\\.version=\"(§§version§§)\"",
        "/\\*! @license DOMPurify (§§version§§)",
        "var .=\"dompurify\"+.{10,550}?\\.version=\"(§§version§§)\""
      ]
    }
  }
};
