# Changelog

Generated from the commit history at release time. The narrative history
through 1.3.0 is in [CHANGES.rst](https://github.com/pysnmp/pyasn1/blob/main/CHANGES.rst).

# [1.3.0-rc.2](https://github.com/pysnmp/pyasn1/compare/v1.3.0-rc.1...v1.3.0-rc.2) (2026-09-05)


### Bug Fixes

* keep the BER decoder's substrateFun path inside PyAsn1Error ([26c1231](https://github.com/pysnmp/pyasn1/commit/26c12316a2d240817a2aacc71d0c0920f9f67dfc)), closes [#140](https://github.com/pysnmp/pyasn1/issues/140) [#142](https://github.com/pysnmp/pyasn1/issues/142)

# [1.3.0-rc.1](https://github.com/pysnmp/pyasn1/compare/v1.2.0...v1.3.0-rc.1) (2026-09-05)


### Bug Fixes

* encode a present OPTIONAL component even when it is empty ([69f4b80](https://github.com/pysnmp/pyasn1/commit/69f4b80e9f195018f0d84929b3b3265a7344c531)), closes [#119](https://github.com/pysnmp/pyasn1/issues/119) [#112](https://github.com/pysnmp/pyasn1/issues/112)
* encoder must not instantiate absent DEFAULT components ([2e7abff](https://github.com/pysnmp/pyasn1/commit/2e7abff0d7110695c669cfa0c43d85d44e31a89a)), closes [#112](https://github.com/pysnmp/pyasn1/issues/112)
* isInconsistent must report an exception, not a bare True ([a16a043](https://github.com/pysnmp/pyasn1/commit/a16a043b71a1f816a824e9911b51be1462a69b3a)), closes [#118](https://github.com/pysnmp/pyasn1/issues/118)
* keep all components when an explicit-tag guess is refuted ([09b9862](https://github.com/pysnmp/pyasn1/commit/09b986217624990eeb226806eb75834b58a59418)), closes [#116](https://github.com/pysnmp/pyasn1/issues/116) [pyasn1/pyasn1#59](https://github.com/pyasn1/pyasn1/issues/59)
* keep the EOO when capturing an untagged Any ([c396c79](https://github.com/pysnmp/pyasn1/commit/c396c799fef37bc700b80c9ba796da65d9bb7ae2)), closes [#114](https://github.com/pysnmp/pyasn1/issues/114) [pyasn1/pyasn1#66](https://github.com/pyasn1/pyasn1/issues/66)
* malformed BIT STRING must raise PyAsn1Error, not IndexError ([6738bec](https://github.com/pysnmp/pyasn1/commit/6738bec819e60d4109b8a53fb3457423fb97c237)), closes [#121](https://github.com/pysnmp/pyasn1/issues/121)
* re-resolve late-bound componentType on clone and subtype ([6e62269](https://github.com/pysnmp/pyasn1/commit/6e6226968321085c4e3af2036ad8e2dfcae6b37b)), closes [#111](https://github.com/pysnmp/pyasn1/issues/111) [pyasn1/pyasn1#124](https://github.com/pyasn1/pyasn1/issues/124) [etingof/pyasn1#19](https://github.com/etingof/pyasn1/issues/19) [etingof/pyasn1#20](https://github.com/etingof/pyasn1/issues/20)
* reading a Choice alternative must not deselect another ([6e5b40a](https://github.com/pysnmp/pyasn1/commit/6e5b40a2672675d3dc187858c1896c2e005bfd48)), closes [#122](https://github.com/pysnmp/pyasn1/issues/122)
* report an ambiguous SEQUENCE schema instead of guessing a component ([a389f1e](https://github.com/pysnmp/pyasn1/commit/a389f1ed693eb7224a0aef35e4d857c92c0d466c)), closes [#120](https://github.com/pysnmp/pyasn1/issues/120) [pyasn1/pyasn1#84](https://github.com/pyasn1/pyasn1/issues/84)
* **security:** bound OID arcs, tag numbers and Real conversion ([0ff4c73](https://github.com/pysnmp/pyasn1/commit/0ff4c73303f553362bf9bf98389f6e899e986f41)), closes [Hi#tag-number](https://github.com/Hi/issues/tag-number) [#110](https://github.com/pysnmp/pyasn1/issues/110)


### Features

* add univ.RelativeOID (X.680 RELATIVE-OID, universal tag 13) ([9e274a0](https://github.com/pysnmp/pyasn1/commit/9e274a0bda1b0d945b8f7bebc52240d52f9234d1)), closes [#117](https://github.com/pysnmp/pyasn1/issues/117) [#110](https://github.com/pysnmp/pyasn1/issues/110)
# [1.2.0](https://github.com/pysnmp/pyasn1/compare/v1.1.3...v1.2.0) (2026-09-03)


### Bug Fixes

* **cer,der:** enforce canonical GeneralizedTime and UTCTime ([ae8e39b](https://github.com/pysnmp/pyasn1/commit/ae8e39b1872570284ef07582d8daa84e253027ce))
* **cer,der:** enforce canonical REAL form per X.690 11.3 ([3b49e2a](https://github.com/pysnmp/pyasn1/commit/3b49e2abf104464ae8cc16f45a6f544f98251546))
* **cer,der:** enforce the string encoding forms of X.690 9.1, 9.2 and 10.2 ([59959fc](https://github.com/pysnmp/pyasn1/commit/59959fcd0fbed6f28660c10d349c58e392c9c526)), closes [#61](https://github.com/pysnmp/pyasn1/issues/61) [#96](https://github.com/pysnmp/pyasn1/issues/96) [#97](https://github.com/pysnmp/pyasn1/issues/97)
* **cer,der:** install strict decoders on the schema-guided path ([44e2ea2](https://github.com/pysnmp/pyasn1/commit/44e2ea2e6fd14b37668164246c9841cbb6811e37))
* **cer,der:** reject non-minimal INTEGER encodings per X.690 8.3.2 ([d37aae1](https://github.com/pysnmp/pyasn1/commit/d37aae110a95e0fbc9234c9f451a0804f6114653))
* **cer,der:** require minimal length and tag identifier forms ([27fdd0d](https://github.com/pysnmp/pyasn1/commit/27fdd0db928ab012b55b84352e750e27c9582372)), closes [#57](https://github.com/pysnmp/pyasn1/issues/57)
* **cer,der:** require zero unused bits in BIT STRING per X.690 11.2.1 ([0768eb1](https://github.com/pysnmp/pyasn1/commit/0768eb133978983b7b209470d532c722ed7c2739)), closes [#61](https://github.com/pysnmp/pyasn1/issues/61)
* **cer:** budget the BIT STRING unused-bits octet when segmenting ([5c9500b](https://github.com/pysnmp/pyasn1/commit/5c9500beff60df7a885a9e7b3f10fad70019e579)), closes [#95](https://github.com/pysnmp/pyasn1/issues/95)
* ci for build ([dbd35eb](https://github.com/pysnmp/pyasn1/commit/dbd35ebd7656a2951f7babe9e59666139e439664))
* ci issue ([add11e0](https://github.com/pysnmp/pyasn1/commit/add11e0f1a0cad332462026c504026e6502775c0))
* ci publish ([b5decec](https://github.com/pysnmp/pyasn1/commit/b5decec4509809c664ca2a345bfc0f01d42f0db5))
* **ci:** keep uv.lock in step with the released version ([91becfb](https://github.com/pysnmp/pyasn1/commit/91becfbdf112a725f47cb9de21b3acc39e5b8004))
* **ci:** pin Black version in lint environment ([27aa746](https://github.com/pysnmp/pyasn1/commit/27aa7465247a643b5955981060d19278ac3f9751))
* cleanup imports ([3f92083](https://github.com/pysnmp/pyasn1/commit/3f92083a04c312f9efed6aad0188b324c66c3e5a))
* **constraint:** make ContainedSubtypeConstraint a union, ratchet mypy ([1591f4a](https://github.com/pysnmp/pyasn1/commit/1591f4aa238f3db9a0959e604c85aa1444c4fcef))
* correct IndentationError in ber/decoder.py nesting level logic ([5f8022e](https://github.com/pysnmp/pyasn1/commit/5f8022e8508ea88ad58e83453d1b7870b553cb02))
* **debug:** stop configuring logging at import time ([da55169](https://github.com/pysnmp/pyasn1/commit/da55169a0b9bc7386d021526072c98869d5d0d4e))
* **debug:** stop mutating caller-named loggers, guard lazy printer init ([4d7f974](https://github.com/pysnmp/pyasn1/commit/4d7f9745b597cb875767cf87ae7f1538bbd32fd2))
* **decoder:** reject encodings clause 8 makes structurally impossible ([dfcec59](https://github.com/pysnmp/pyasn1/commit/dfcec5937508b00b59d2652c6c62fcf0f0d5ca29))
* **encoder:** emit INTEGER in the fewest octets X.690 8.3.2 allows ([95befaa](https://github.com/pysnmp/pyasn1/commit/95befaa9f901b44615962323a87aa6e525603178)), closes [#63](https://github.com/pysnmp/pyasn1/issues/63)
* import and flake8 reported issues ([eafee06](https://github.com/pysnmp/pyasn1/commit/eafee061ee715d5ee1cccdff8cd66b98a147e246))
* make schema-object comparison consistent, rewrite NoValue ([086b46c](https://github.com/pysnmp/pyasn1/commit/086b46c6b40b31024e0b87b4f0db75920400b68c))
* **real,useful:** hold decimal REAL to its declared ISO 6093 form ([04bc59d](https://github.com/pysnmp/pyasn1/commit/04bc59d9aae7734bd3e7f1a04c945953af821e92))
* **real:** decode NOT-A-NUMBER and minus zero per X.690 8.5.9 ([c29d30a](https://github.com/pysnmp/pyasn1/commit/c29d30a4ec341fd816a6d317c0da60b65416b72d))
* **real:** keep the base 10 mantissa exact and integral ([43221c8](https://github.com/pysnmp/pyasn1/commit/43221c8351a4f3122685d2e3187b54c7a6895c9b)), closes [#78](https://github.com/pysnmp/pyasn1/issues/78)
* remove duplicate tag helpers ([5fb3905](https://github.com/pysnmp/pyasn1/commit/5fb3905477e7ef134512e7c57ca6e281e256946c))
* **type:** check component presence in InnerTypeConstraint ([640b67e](https://github.com/pysnmp/pyasn1/commit/640b67ee3ad44f38357e4907ed573154caf7c589)), closes [#77](https://github.com/pysnmp/pyasn1/issues/77)
* **type:** render BitString as bits rather than a decimal integer ([861089c](https://github.com/pysnmp/pyasn1/commit/861089c280bfab7139742d38507499512da6e381)), closes [#98](https://github.com/pysnmp/pyasn1/issues/98)
* **type:** stop shadowing pyasn1.error.ValueConstraintError ([99c3b86](https://github.com/pysnmp/pyasn1/commit/99c3b86917d165b76bf283ce8474d4ac31e27e0e)), closes [#103](https://github.com/pysnmp/pyasn1/issues/103)
* **univ:** align Real comparison params with base, add advisory ty check ([5f66b2e](https://github.com/pysnmp/pyasn1/commit/5f66b2e37a083f256a98c695bd2aeec6c0b538dc))
* **useful:** correct time conversion and render times as timestamps ([5659197](https://github.com/pysnmp/pyasn1/commit/565919718a81c806594dee34781afbe338c666f1)), closes [#73](https://github.com/pysnmp/pyasn1/issues/73)


### Features

* **char:** ship opt-in per-type permitted alphabets (X.680 41) ([6b6a726](https://github.com/pysnmp/pyasn1/commit/6b6a72650b1616ba48aaa3ed62650f77c8066d4b)), closes [#74](https://github.com/pysnmp/pyasn1/issues/74)
* deprecate text decoding in OctetString.__str__() ([88864fa](https://github.com/pysnmp/pyasn1/commit/88864fa80ab283891e560e124c6aa3934f9eaf20))
* **error:** carry structured context on exceptions ([0b53353](https://github.com/pysnmp/pyasn1/commit/0b533533d38372e2d51bf75ac801881f337e296a))
* **typing:** add mypy gate, py.typed marker, and baseline annotations ([5a83791](https://github.com/pysnmp/pyasn1/commit/5a83791eb246b97f0d86407c8cc2f123fd00b976))
* **typing:** annotate codec modules and leaf types ([662a987](https://github.com/pysnmp/pyasn1/commit/662a9870f4ee51e2e306f99ba14cb704b23d5f11))
* **typing:** annotate pyasn1.type.base ([b86258d](https://github.com/pysnmp/pyasn1/commit/b86258d6ab6030d354fdc15291282bf577bf47fb))
* **typing:** annotate pyasn1.type.namedtype ([7ea6a2f](https://github.com/pysnmp/pyasn1/commit/7ea6a2f635d97072f9e185ab02ba677b39122a05))
* **typing:** annotate pyasn1.type.univ, completing the codebase ([08feeb1](https://github.com/pysnmp/pyasn1/commit/08feeb152256165f9740ef040802abc19ed16472))
* **typing:** annotate tag, constraint, namedval and opentype ([4750ec5](https://github.com/pysnmp/pyasn1/commit/4750ec56cc0ca455b04467a4a67c98dbd6004b48))
# [1.2.0-rc.1](https://github.com/pysnmp/pyasn1/compare/v1.1.3...v1.2.0-rc.1) (2026-09-03)


### Bug Fixes

* **cer,der:** enforce canonical GeneralizedTime and UTCTime ([ae8e39b](https://github.com/pysnmp/pyasn1/commit/ae8e39b1872570284ef07582d8daa84e253027ce))
* **cer,der:** enforce canonical REAL form per X.690 11.3 ([3b49e2a](https://github.com/pysnmp/pyasn1/commit/3b49e2abf104464ae8cc16f45a6f544f98251546))
* **cer,der:** enforce the string encoding forms of X.690 9.1, 9.2 and 10.2 ([59959fc](https://github.com/pysnmp/pyasn1/commit/59959fcd0fbed6f28660c10d349c58e392c9c526)), closes [#61](https://github.com/pysnmp/pyasn1/issues/61) [#96](https://github.com/pysnmp/pyasn1/issues/96) [#97](https://github.com/pysnmp/pyasn1/issues/97)
* **cer,der:** install strict decoders on the schema-guided path ([44e2ea2](https://github.com/pysnmp/pyasn1/commit/44e2ea2e6fd14b37668164246c9841cbb6811e37))
* **cer,der:** reject non-minimal INTEGER encodings per X.690 8.3.2 ([d37aae1](https://github.com/pysnmp/pyasn1/commit/d37aae110a95e0fbc9234c9f451a0804f6114653))
* **cer,der:** require minimal length and tag identifier forms ([27fdd0d](https://github.com/pysnmp/pyasn1/commit/27fdd0db928ab012b55b84352e750e27c9582372)), closes [#57](https://github.com/pysnmp/pyasn1/issues/57)
* **cer,der:** require zero unused bits in BIT STRING per X.690 11.2.1 ([0768eb1](https://github.com/pysnmp/pyasn1/commit/0768eb133978983b7b209470d532c722ed7c2739)), closes [#61](https://github.com/pysnmp/pyasn1/issues/61)
* **cer:** budget the BIT STRING unused-bits octet when segmenting ([5c9500b](https://github.com/pysnmp/pyasn1/commit/5c9500beff60df7a885a9e7b3f10fad70019e579)), closes [#95](https://github.com/pysnmp/pyasn1/issues/95)
* ci for build ([dbd35eb](https://github.com/pysnmp/pyasn1/commit/dbd35ebd7656a2951f7babe9e59666139e439664))
* ci issue ([add11e0](https://github.com/pysnmp/pyasn1/commit/add11e0f1a0cad332462026c504026e6502775c0))
* ci publish ([b5decec](https://github.com/pysnmp/pyasn1/commit/b5decec4509809c664ca2a345bfc0f01d42f0db5))
* **ci:** keep uv.lock in step with the released version ([91becfb](https://github.com/pysnmp/pyasn1/commit/91becfbdf112a725f47cb9de21b3acc39e5b8004))
* **ci:** pin Black version in lint environment ([27aa746](https://github.com/pysnmp/pyasn1/commit/27aa7465247a643b5955981060d19278ac3f9751))
* cleanup imports ([3f92083](https://github.com/pysnmp/pyasn1/commit/3f92083a04c312f9efed6aad0188b324c66c3e5a))
* **constraint:** make ContainedSubtypeConstraint a union, ratchet mypy ([1591f4a](https://github.com/pysnmp/pyasn1/commit/1591f4aa238f3db9a0959e604c85aa1444c4fcef))
* correct IndentationError in ber/decoder.py nesting level logic ([5f8022e](https://github.com/pysnmp/pyasn1/commit/5f8022e8508ea88ad58e83453d1b7870b553cb02))
* **debug:** stop configuring logging at import time ([da55169](https://github.com/pysnmp/pyasn1/commit/da55169a0b9bc7386d021526072c98869d5d0d4e))
* **debug:** stop mutating caller-named loggers, guard lazy printer init ([4d7f974](https://github.com/pysnmp/pyasn1/commit/4d7f9745b597cb875767cf87ae7f1538bbd32fd2))
* **decoder:** reject encodings clause 8 makes structurally impossible ([dfcec59](https://github.com/pysnmp/pyasn1/commit/dfcec5937508b00b59d2652c6c62fcf0f0d5ca29))
* **encoder:** emit INTEGER in the fewest octets X.690 8.3.2 allows ([95befaa](https://github.com/pysnmp/pyasn1/commit/95befaa9f901b44615962323a87aa6e525603178)), closes [#63](https://github.com/pysnmp/pyasn1/issues/63)
* import and flake8 reported issues ([eafee06](https://github.com/pysnmp/pyasn1/commit/eafee061ee715d5ee1cccdff8cd66b98a147e246))
* make schema-object comparison consistent, rewrite NoValue ([086b46c](https://github.com/pysnmp/pyasn1/commit/086b46c6b40b31024e0b87b4f0db75920400b68c))
* **real,useful:** hold decimal REAL to its declared ISO 6093 form ([04bc59d](https://github.com/pysnmp/pyasn1/commit/04bc59d9aae7734bd3e7f1a04c945953af821e92))
* **real:** decode NOT-A-NUMBER and minus zero per X.690 8.5.9 ([c29d30a](https://github.com/pysnmp/pyasn1/commit/c29d30a4ec341fd816a6d317c0da60b65416b72d))
* **real:** keep the base 10 mantissa exact and integral ([43221c8](https://github.com/pysnmp/pyasn1/commit/43221c8351a4f3122685d2e3187b54c7a6895c9b)), closes [#78](https://github.com/pysnmp/pyasn1/issues/78)
* remove duplicate tag helpers ([5fb3905](https://github.com/pysnmp/pyasn1/commit/5fb3905477e7ef134512e7c57ca6e281e256946c))
* **type:** check component presence in InnerTypeConstraint ([640b67e](https://github.com/pysnmp/pyasn1/commit/640b67ee3ad44f38357e4907ed573154caf7c589)), closes [#77](https://github.com/pysnmp/pyasn1/issues/77)
* **type:** render BitString as bits rather than a decimal integer ([861089c](https://github.com/pysnmp/pyasn1/commit/861089c280bfab7139742d38507499512da6e381)), closes [#98](https://github.com/pysnmp/pyasn1/issues/98)
* **type:** stop shadowing pyasn1.error.ValueConstraintError ([99c3b86](https://github.com/pysnmp/pyasn1/commit/99c3b86917d165b76bf283ce8474d4ac31e27e0e)), closes [#103](https://github.com/pysnmp/pyasn1/issues/103)
* **univ:** align Real comparison params with base, add advisory ty check ([5f66b2e](https://github.com/pysnmp/pyasn1/commit/5f66b2e37a083f256a98c695bd2aeec6c0b538dc))
* **useful:** correct time conversion and render times as timestamps ([5659197](https://github.com/pysnmp/pyasn1/commit/565919718a81c806594dee34781afbe338c666f1)), closes [#73](https://github.com/pysnmp/pyasn1/issues/73)


### Features

* **char:** ship opt-in per-type permitted alphabets (X.680 41) ([6b6a726](https://github.com/pysnmp/pyasn1/commit/6b6a72650b1616ba48aaa3ed62650f77c8066d4b)), closes [#74](https://github.com/pysnmp/pyasn1/issues/74)
* deprecate text decoding in OctetString.__str__() ([88864fa](https://github.com/pysnmp/pyasn1/commit/88864fa80ab283891e560e124c6aa3934f9eaf20))
* **error:** carry structured context on exceptions ([0b53353](https://github.com/pysnmp/pyasn1/commit/0b533533d38372e2d51bf75ac801881f337e296a))
* **typing:** add mypy gate, py.typed marker, and baseline annotations ([5a83791](https://github.com/pysnmp/pyasn1/commit/5a83791eb246b97f0d86407c8cc2f123fd00b976))
* **typing:** annotate codec modules and leaf types ([662a987](https://github.com/pysnmp/pyasn1/commit/662a9870f4ee51e2e306f99ba14cb704b23d5f11))
* **typing:** annotate pyasn1.type.base ([b86258d](https://github.com/pysnmp/pyasn1/commit/b86258d6ab6030d354fdc15291282bf577bf47fb))
* **typing:** annotate pyasn1.type.namedtype ([7ea6a2f](https://github.com/pysnmp/pyasn1/commit/7ea6a2f635d97072f9e185ab02ba677b39122a05))
* **typing:** annotate pyasn1.type.univ, completing the codebase ([08feeb1](https://github.com/pysnmp/pyasn1/commit/08feeb152256165f9740ef040802abc19ed16472))
* **typing:** annotate tag, constraint, namedval and opentype ([4750ec5](https://github.com/pysnmp/pyasn1/commit/4750ec56cc0ca455b04467a4a67c98dbd6004b48))
# [1.2.0-beta.14](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.13...v1.2.0-beta.14) (2026-09-02)


### Bug Fixes

* **real,useful:** hold decimal REAL to its declared ISO 6093 form ([04bc59d](https://github.com/pysnmp/pyasn1/commit/04bc59d9aae7734bd3e7f1a04c945953af821e92))
* **real:** keep the base 10 mantissa exact and integral ([43221c8](https://github.com/pysnmp/pyasn1/commit/43221c8351a4f3122685d2e3187b54c7a6895c9b)), closes [#78](https://github.com/pysnmp/pyasn1/issues/78)
* **type:** stop shadowing pyasn1.error.ValueConstraintError ([99c3b86](https://github.com/pysnmp/pyasn1/commit/99c3b86917d165b76bf283ce8474d4ac31e27e0e)), closes [#103](https://github.com/pysnmp/pyasn1/issues/103)
* **useful:** correct time conversion and render times as timestamps ([5659197](https://github.com/pysnmp/pyasn1/commit/565919718a81c806594dee34781afbe338c666f1)), closes [#73](https://github.com/pysnmp/pyasn1/issues/73)


### Features

* **char:** ship opt-in per-type permitted alphabets (X.680 41) ([6b6a726](https://github.com/pysnmp/pyasn1/commit/6b6a72650b1616ba48aaa3ed62650f77c8066d4b)), closes [#74](https://github.com/pysnmp/pyasn1/issues/74)
# [1.2.0-beta.13](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.12...v1.2.0-beta.13) (2026-09-02)


### Bug Fixes

* **cer,der:** require minimal length and tag identifier forms ([27fdd0d](https://github.com/pysnmp/pyasn1/commit/27fdd0db928ab012b55b84352e750e27c9582372)), closes [#57](https://github.com/pysnmp/pyasn1/issues/57)
* **type:** check component presence in InnerTypeConstraint ([640b67e](https://github.com/pysnmp/pyasn1/commit/640b67ee3ad44f38357e4907ed573154caf7c589)), closes [#77](https://github.com/pysnmp/pyasn1/issues/77)
* **type:** render BitString as bits rather than a decimal integer ([861089c](https://github.com/pysnmp/pyasn1/commit/861089c280bfab7139742d38507499512da6e381)), closes [#98](https://github.com/pysnmp/pyasn1/issues/98)
# [1.2.0-beta.12](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.11...v1.2.0-beta.12) (2026-09-02)


### Bug Fixes

* **cer,der:** enforce the string encoding forms of X.690 9.1, 9.2 and 10.2 ([59959fc](https://github.com/pysnmp/pyasn1/commit/59959fcd0fbed6f28660c10d349c58e392c9c526)), closes [#61](https://github.com/pysnmp/pyasn1/issues/61) [#96](https://github.com/pysnmp/pyasn1/issues/96) [#97](https://github.com/pysnmp/pyasn1/issues/97)
* **cer:** budget the BIT STRING unused-bits octet when segmenting ([5c9500b](https://github.com/pysnmp/pyasn1/commit/5c9500beff60df7a885a9e7b3f10fad70019e579)), closes [#95](https://github.com/pysnmp/pyasn1/issues/95)
# [1.2.0-beta.11](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.10...v1.2.0-beta.11) (2026-09-02)


### Bug Fixes

* **cer,der:** enforce canonical REAL form per X.690 11.3 ([3b49e2a](https://github.com/pysnmp/pyasn1/commit/3b49e2abf104464ae8cc16f45a6f544f98251546))
# [1.2.0-beta.10](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.9...v1.2.0-beta.10) (2026-09-02)


### Bug Fixes

* **cer,der:** reject non-minimal INTEGER encodings per X.690 8.3.2 ([d37aae1](https://github.com/pysnmp/pyasn1/commit/d37aae110a95e0fbc9234c9f451a0804f6114653))
# [1.2.0-beta.9](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.8...v1.2.0-beta.9) (2026-09-02)


### Bug Fixes

* **cer,der:** enforce canonical GeneralizedTime and UTCTime ([ae8e39b](https://github.com/pysnmp/pyasn1/commit/ae8e39b1872570284ef07582d8daa84e253027ce))
# [1.2.0-beta.8](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.7...v1.2.0-beta.8) (2026-09-02)


### Bug Fixes

* **cer,der:** install strict decoders on the schema-guided path ([44e2ea2](https://github.com/pysnmp/pyasn1/commit/44e2ea2e6fd14b37668164246c9841cbb6811e37))
* **cer,der:** require zero unused bits in BIT STRING per X.690 11.2.1 ([0768eb1](https://github.com/pysnmp/pyasn1/commit/0768eb133978983b7b209470d532c722ed7c2739)), closes [#61](https://github.com/pysnmp/pyasn1/issues/61)
* **decoder:** reject encodings clause 8 makes structurally impossible ([dfcec59](https://github.com/pysnmp/pyasn1/commit/dfcec5937508b00b59d2652c6c62fcf0f0d5ca29))
* **real:** decode NOT-A-NUMBER and minus zero per X.690 8.5.9 ([c29d30a](https://github.com/pysnmp/pyasn1/commit/c29d30a4ec341fd816a6d317c0da60b65416b72d))
# [1.2.0-beta.7](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.6...v1.2.0-beta.7) (2026-09-02)


### Bug Fixes

* **encoder:** emit INTEGER in the fewest octets X.690 8.3.2 allows ([95befaa](https://github.com/pysnmp/pyasn1/commit/95befaa9f901b44615962323a87aa6e525603178)), closes [#63](https://github.com/pysnmp/pyasn1/issues/63)
# [1.2.0-beta.6](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.5...v1.2.0-beta.6) (2026-09-02)


### Features

* **error:** carry structured context on exceptions ([0b53353](https://github.com/pysnmp/pyasn1/commit/0b533533d38372e2d51bf75ac801881f337e296a))
# [1.2.0-beta.5](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.4...v1.2.0-beta.5) (2026-09-02)


### Bug Fixes

* remove duplicate tag helpers ([5fb3905](https://github.com/pysnmp/pyasn1/commit/5fb3905477e7ef134512e7c57ca6e281e256946c))
# [1.2.0-beta.4](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.3...v1.2.0-beta.4) (2026-09-01)


### Bug Fixes

* **debug:** stop configuring logging at import time ([da55169](https://github.com/pysnmp/pyasn1/commit/da55169a0b9bc7386d021526072c98869d5d0d4e))
* **debug:** stop mutating caller-named loggers, guard lazy printer init ([4d7f974](https://github.com/pysnmp/pyasn1/commit/4d7f9745b597cb875767cf87ae7f1538bbd32fd2))
# [1.2.0-beta.3](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.2...v1.2.0-beta.3) (2026-09-01)


### Bug Fixes

* **constraint:** make ContainedSubtypeConstraint a union, ratchet mypy ([1591f4a](https://github.com/pysnmp/pyasn1/commit/1591f4aa238f3db9a0959e604c85aa1444c4fcef))
* **univ:** align Real comparison params with base, add advisory ty check ([5f66b2e](https://github.com/pysnmp/pyasn1/commit/5f66b2e37a083f256a98c695bd2aeec6c0b538dc))


### Features

* **typing:** annotate codec modules and leaf types ([662a987](https://github.com/pysnmp/pyasn1/commit/662a9870f4ee51e2e306f99ba14cb704b23d5f11))
* **typing:** annotate pyasn1.type.base ([b86258d](https://github.com/pysnmp/pyasn1/commit/b86258d6ab6030d354fdc15291282bf577bf47fb))
* **typing:** annotate pyasn1.type.namedtype ([7ea6a2f](https://github.com/pysnmp/pyasn1/commit/7ea6a2f635d97072f9e185ab02ba677b39122a05))
* **typing:** annotate pyasn1.type.univ, completing the codebase ([08feeb1](https://github.com/pysnmp/pyasn1/commit/08feeb152256165f9740ef040802abc19ed16472))
* **typing:** annotate tag, constraint, namedval and opentype ([4750ec5](https://github.com/pysnmp/pyasn1/commit/4750ec56cc0ca455b04467a4a67c98dbd6004b48))
# [1.2.0-beta.2](https://github.com/pysnmp/pyasn1/compare/v1.2.0-beta.1...v1.2.0-beta.2) (2026-09-01)


### Features

* **typing:** add mypy gate, py.typed marker, and baseline annotations ([5a83791](https://github.com/pysnmp/pyasn1/commit/5a83791eb246b97f0d86407c8cc2f123fd00b976))
# [1.2.0-beta.1](https://github.com/pysnmp/pyasn1/compare/v1.1.4-beta.8...v1.2.0-beta.1) (2026-09-01)


### Features

* deprecate text decoding in OctetString.__str__() ([88864fa](https://github.com/pysnmp/pyasn1/commit/88864fa80ab283891e560e124c6aa3934f9eaf20))
## [1.1.4-beta.8](https://github.com/pysnmp/pyasn1/compare/v1.1.4-beta.7...v1.1.4-beta.8) (2026-09-01)


### Bug Fixes

* **ci:** keep uv.lock in step with the released version ([91becfb](https://github.com/pysnmp/pyasn1/commit/91becfbdf112a725f47cb9de21b3acc39e5b8004))
## [1.1.4-beta.7](https://github.com/pysnmp/pyasn1/compare/v1.1.4-beta.6...v1.1.4-beta.7) (2026-09-01)


### Bug Fixes

* make schema-object comparison consistent, rewrite NoValue ([086b46c](https://github.com/pysnmp/pyasn1/commit/086b46c6b40b31024e0b87b4f0db75920400b68c))
## [1.1.4-beta.6](https://github.com/pysnmp/pyasn1/compare/v1.1.4-beta.5...v1.1.4-beta.6) (2026-09-01)


### Bug Fixes

* correct IndentationError in ber/decoder.py nesting level logic ([5f8022e](https://github.com/pysnmp/pyasn1/commit/5f8022e8508ea88ad58e83453d1b7870b553cb02))
## [1.1.4-beta.5](https://github.com/pysnmp/pyasn1/compare/v1.1.4-beta.4...v1.1.4-beta.5) (2026-09-01)


### Bug Fixes

* **ci:** pin Black version in lint environment ([27aa746](https://github.com/pysnmp/pyasn1/commit/27aa7465247a643b5955981060d19278ac3f9751))
## [1.1.4-beta.4](https://github.com/pysnmp/pyasn1/compare/v1.1.4-beta.3...v1.1.4-beta.4) (2025-05-20)


### Bug Fixes

* ci publish ([b5decec](https://github.com/pysnmp/pyasn1/commit/b5decec4509809c664ca2a345bfc0f01d42f0db5))
## [1.1.4-beta.3](https://github.com/pysnmp/pyasn1/compare/v1.1.4-beta.2...v1.1.4-beta.3) (2025-05-20)


### Bug Fixes

* ci issue ([add11e0](https://github.com/pysnmp/pyasn1/commit/add11e0f1a0cad332462026c504026e6502775c0))
## [1.1.3](https://github.com/pysnmp/pyasn1/compare/v1.1.2...v1.1.3) (2023-02-21)


### Bug Fixes

* bring back missing ints2octs and ensureString ([bc81772](https://github.com/pysnmp/pyasn1/commit/bc81772d2048a00bc327691771123ca6f0e867c4))
* bring back missing ints2octs and ensureString ([c92da99](https://github.com/pysnmp/pyasn1/commit/c92da9958eb238baede01c1f8317ab6cae3318a4))
* CI ([ad8f444](https://github.com/pysnmp/pyasn1/commit/ad8f44488468ce7fe21b1daae738c496ca249cc7))
* delete agreements from CI ([525381a](https://github.com/pysnmp/pyasn1/commit/525381a93f67f9eb14d6f9d30fd2f143bb0f77ad))
* ints2octes issue ([7076275](https://github.com/pysnmp/pyasn1/commit/70762756eb00354fad54a518fa29c3fdcf903dec))
* make codecov not required ([1b9e949](https://github.com/pysnmp/pyasn1/commit/1b9e9490f81ff6180b6c811a45bd46d82f18f68f))
* run pre-commit and update pre-commit workflow ([7bdab33](https://github.com/pysnmp/pyasn1/commit/7bdab3303a83f50cd088cfc0582c26fb5ba33850))
* upgrade pre-commit version ([c388965](https://github.com/pysnmp/pyasn1/commit/c388965c509138e760af95eacc7c13d3738649c7))
* upgrade semantic release ([51b9338](https://github.com/pysnmp/pyasn1/commit/51b93381f1c119c330cd7279ddf6b59da1955357))
## [1.1.2](https://github.com/pysnmp/pyasn1/compare/v1.1.1...v1.1.2) (2021-11-24)


### Bug Fixes

* cleanup old code ([c92b584](https://github.com/pysnmp/pyasn1/commit/c92b584ba8380430f6cfa7fc265119f87d40705e))
## [1.1.1](https://github.com/pysnmp/pyasn1/compare/v1.1.0...v1.1.1) (2021-11-24)


### Bug Fixes

* remove shadow ([57a2495](https://github.com/pysnmp/pyasn1/commit/57a2495606a1d9b4b8a7c599176096de4484d863))
# [1.1.0](https://github.com/pysnmp/pyasn1/compare/v1.0.3...v1.1.0) (2021-11-24)


### Bug Fixes

* format issues ([b935c31](https://github.com/pysnmp/pyasn1/commit/b935c31188693a2e268d0fee4231ff8361fb45af))
* remove dead code ([3f21cc6](https://github.com/pysnmp/pyasn1/commit/3f21cc6e7d4e4d868f08f8ff394303f3008ef996))


### Features

* format with black ([1824a3a](https://github.com/pysnmp/pyasn1/commit/1824a3a80885040d288e3ddbd6b6cdba9aec71b2))
## [1.0.3](https://github.com/pysnmp/pyasn1/compare/v1.0.2...v1.0.3) (2021-11-17)


### Bug Fixes

* bump ([ec35ee1](https://github.com/pysnmp/pyasn1/commit/ec35ee198b80f285df472c3b4059bb59ca056d7f))
## [1.0.2](https://github.com/pysnmp/pyasn1/compare/v1.0.1...v1.0.2) (2021-11-13)


### Bug Fixes

* bump version ([a6d7a5e](https://github.com/pysnmp/pyasn1/commit/a6d7a5eff6b5b4875ada2abc2c3d928d1f0d9fae))
## [1.0.1](https://github.com/pysnmp/pyasn1/compare/v1.0.0...v1.0.1) (2021-11-13)


### Bug Fixes

* bump ([970e15d](https://github.com/pysnmp/pyasn1/commit/970e15d47e33906020735242eea6bb2ad1f53af0))
**Full Changelog**: https://github.com/pysnmp/pyasn1/compare/0.4.8...v1.0.0
## [0.4.12](https://github.com/pysnmp/pyasn1/compare/v0.4.11...v0.4.12) (2021-11-13)


### Bug Fixes

* Update doc links ([9cabd9b](https://github.com/pysnmp/pyasn1/commit/9cabd9b0a273a3f5afaeb36387f6bb4cf92a7802))
## [0.4.11](https://github.com/pysnmp/pyasn1/compare/v0.4.10...v0.4.11) (2021-11-13)


### Bug Fixes

* correct badges ([4cbde56](https://github.com/pysnmp/pyasn1/commit/4cbde5679aa15835372a9cec6c9ccd7503168229))
## [0.4.10](https://github.com/pysnmp/pyasn1/compare/v0.4.9...v0.4.10) (2021-11-13)


### Bug Fixes

* correct readme ref ([732a4a6](https://github.com/pysnmp/pyasn1/commit/732a4a69a54e018dc3ef0493b7d07af23aeb8cc4))
* update classifiers ([b3fa5d6](https://github.com/pysnmp/pyasn1/commit/b3fa5d6aff60d2b677c99d46d29b4dabf06b69ef))
## [0.4.9](https://github.com/pysnmp/pyasn1/compare/v0.4.8...v0.4.9) (2021-11-13)


### Bug Fixes

* update gitignore ([c8f0be6](https://github.com/pysnmp/pyasn1/commit/c8f0be6885a3984032325d449838370052f9cfd4))


### Reverts

* change ([a6ac7b5](https://github.com/pysnmp/pyasn1/commit/a6ac7b5ad860b84e919cd691405a2726a7aec569))
