# Change Log

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

<a name="0.1.5"></a>
## [0.1.5](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.1.4...v0.1.5) (2020-08-13)


### Features

* **go.mod:** go.mod ([4118334](http://git.hyperchain.cn/ultramesh/crypto/commits/4118334))



<a name="0.1.4"></a>
## [0.1.4](http://git.hyperchain.cn/ultramesh/crypto/compare/v0.1.3...v0.1.4) (2020-07-25)


### Bug Fixes

* **ci:** port ([d27ab91](http://git.hyperchain.cn/ultramesh/crypto/commits/d27ab91))
* **sm2:** fix some bug with new gm.sm2PrivateKey ([d803159](http://git.hyperchain.cn/ultramesh/crypto/commits/d803159))


### Features

* **ci:** fix ci ([2f56565](http://git.hyperchain.cn/ultramesh/crypto/commits/2f56565))
* **crl:** add crl and delete gitlib-ci.yml ([f848878](http://git.hyperchain.cn/ultramesh/crypto/commits/f848878))
* **pem.go:** encryption pem ([b424a63](http://git.hyperchain.cn/ultramesh/crypto/commits/b424a63))
* **ra:** fix ra ([d1ef560](http://git.hyperchain.cn/ultramesh/crypto/commits/d1ef560))
* **sonar:** add sonar-project.properties ([3ffd07c](http://git.hyperchain.cn/ultramesh/crypto/commits/3ffd07c))
* **test:** random net port for test ([eca4a46](http://git.hyperchain.cn/ultramesh/crypto/commits/eca4a46))



# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.1.3](///compare/v0.1.2...v0.1.3) (2020-04-10)


### Features

* **cert_util:** add TestSM2Verify ([3898c5a](///commit/3898c5a49e3d0050bfe1c39f52a5f9d9936cadee))
* **changelog:** revert 0.1.3 ([f4323fb](///commit/f4323fba72f8218c9498987b13bb83f5c7f705ea))
* **crl:** test for darwin ([e6b6277](///commit/e6b627759de316f6cf978e877ba562e26b9b3e61))
* **feat:** add gmssl certificate verify ([6f26871](///commit/6f2687171202b70f899e3aa9edb6bbd172a3e889))
* **feat:** add self signed cert from private and public key ([a95d55f](///commit/a95d55f36f0ed669b50b6af8173da8867475b24c))
* **go.mod:** update version ([cb9f3bf](///commit/cb9f3bf8420d1f5aa3735e0bebbe59377e1da4a1))
* **private:** fix internal ([af803e8](///commit/af803e8d2febb3061c79d06a2e0cfa9c58e67610))


### Bug Fixes

* **primitives/crl_test:** fix some error in golint ([e4029de](///commit/e4029de913bc7f0c65ce2b9878b846907bee5cc1))
* **primitives/crl_test:** use local crl server to get certificateList ([2195111](///commit/219511183f56bd8b6596f4071110816db2a35bb0))
* **test:** fix some golint error in test function ([9252bf7](///commit/9252bf703cbfaa78dad1a43fd361f66fe5768921))
* **tls:** change verifyHostname using www.baidu.com to localhost, fix some mistake in primitive ([4101848](///commit/4101848731465034dffb469f8a6aace60828fb40))
* **tls:** change verifyHostname using www.baidu.com to localhost, fix some mistake in primitive ([c9a233f](///commit/c9a233f40f5bb1755b6962a4c60bec335c3425af))
* **tls:** fix some test in primitives, add test function about secp256k1 and sm2 in tls ([53a9f48](///commit/53a9f48039848d7906e54e14a28a85a5f38456dd))
* **tls:** fix some test in primitives, add test function about secp256k1 and sm2 in tls ([7bb7ce1](///commit/7bb7ce15b5891a3e4666712b6872db77cbc08db5))

### [0.1.2](///compare/v0.1.1...v0.1.2) (2020-03-19)


### Features

* **all:** remove ecdsa ([948df9e](///commit/948df9e0a99359d955cdde329cf824cd986286bc))
* **all:** remove ecdsa` ([6fe4b89](///commit/6fe4b8918f1774d7195b566ab0a9d33c23b9c9c9))
* **all:** remove_ecdsa_package ([8fcd93d](///commit/8fcd93d5208f60c9caa931e6184c41524798ae0f))
* **go.mod:** update crypto version ([6566ae4](///commit/6566ae4c8e8aa495620dd4234a6f7c3270c89f8d))


### Bug Fixes

* **pem.go:** pemTypeCertificate ([b12183e](///commit/b12183e58760e4d510306f520980d13eab535432))
* **x509/sm2:** repalce x509.PrivateKey with crypto-gm.SM2PrivateKey ([a3a14a5](///commit/a3a14a552fe2aebb1ae1e1d2848d9f628e910f0b))

### [0.1.1](///compare/v0.1.0...v0.1.1) (2019-12-21)


### Features

* **key:** #flato-955, add rand reader ([62391ef](///commit/62391ef4b913306ddb36994fdbe111cf5bd1b6dd)), closes [#flato-955](///issues/flato-955)
* **README.md:** modify README.md ([e93dd31](///commit/e93dd31ab108a20a17b43185871e0de5e4610c5c))
* **test:** remove failpoint ([b68f987](///commit/b68f9879da9e78aa1d54913d9160a4317ef5576d))
* **tests:** increase test coverage ([71cab60](///commit/71cab60c1eb00dc9fd996130c7bba793bdf04f02))


### Bug Fixes

* **script,go.mod:** change script and go.mod ([6a827d3](///commit/6a827d3ddb439d1619cb7ae1901fcf8f522efde2))

## 0.1.0 (2019-08-23)


### Bug Fixes

* **all:** update goalngci-lint ([edb6770](///commit/edb6770))
* **log.go:** log ([26efce7](///commit/26efce7))
* **log.go:** log ([a09d987](///commit/a09d987))
* **script,go.mod:** change script and go.mod ([6a827d3](///commit/6a827d3))
* pfx ([2f80394](///commit/2f80394))


### Features

* **camanager:** first init msp cert repo ([bf5981e](///commit/bf5981e))
* **cert_util.go:** change function para type ([de35999](///commit/de35999))
* **generateCert:** add cert generation ([6acd3b7](///commit/6acd3b7))
* **log:** add log ([aadee85](///commit/aadee85))
* **pre-commit:** add pre-commit ([2bc18ed](///commit/2bc18ed))
* **primitives:** init ([9502f20](///commit/9502f20))
* **primitives:** init ([1a26f9b](///commit/1a26f9b))
* **test:** add tests of primitives ([290ea39](///commit/290ea39))
* **test:** remove failpoint ([b68f987](///commit/b68f987))
* **tests:** add tests of primitives ([1422226](///commit/1422226))
* **tests:** increase test coverage ([71cab60](///commit/71cab60))
* **tls:** add guomi tls, not finish ([d46a18b](///commit/d46a18b))
* **tls:** add https unit test ([f3755e9](///commit/f3755e9))
* **tls:** add https_test ([ee04490](///commit/ee04490))
* **tls:** add tls ([7013ebf](///commit/7013ebf))
* **tls:** tls ([674d2b8](///commit/674d2b8))
* **tls:** tls ([dea5258](///commit/dea5258))
* **tls:** tls support guomi ([ad14f1a](///commit/ad14f1a))
* **vendor:** add go mod and delete vendor ([7d031d0](///commit/7d031d0))
* **vendor:** fix verndor golang_.org ([201caa4](///commit/201caa4))
* **verndor/golang.org/x/sys:** add verndor ([462cedb](///commit/462cedb))
* **x509:** ci ([a9cd659](///commit/a9cd659))
