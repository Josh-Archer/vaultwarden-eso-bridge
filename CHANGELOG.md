# Changelog

## [0.5.0](https://github.com/Josh-Archer/vaultwarden-eso-bridge/compare/v0.4.0...v0.5.0) (2026-08-30)


### Features

* **backend:** native Bitwarden Secrets Manager (BWS) machine account provider ([#28](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/28)) ([#38](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/38)) ([b1e03ad](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/b1e03adb83c27e96e2594bbacd9d99f6b85d718c))

## [0.4.0](https://github.com/Josh-Archer/vaultwarden-eso-bridge/compare/v0.3.0...v0.4.0) (2026-08-30)


### Features

* **security:** Kubernetes ServiceAccount TokenReview authentication and TLS ([#27](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/27)) ([#36](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/36)) ([a59e784](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/a59e7848ca1399e2c71ef03432ae1a5cd9acda28))

## [0.3.0](https://github.com/Josh-Archer/vaultwarden-eso-bridge/compare/v0.2.0...v0.3.0) (2026-08-30)


### Features

* **api:** add multi-key bulk JSON, negative caching, and file attachments ([#19](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/19), [#20](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/20), [#23](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/23)) ([#32](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/32)) ([43f19ea](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/43f19eac0d2e74a705ba5894b3f2ee61393051d8))
* **api:** add POST /v1/admin/ensure and /v1/admin/rotate endpoints ([#21](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/21)) ([#35](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/35)) ([03b1021](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/03b10211688ee2cd8350ae91b7f49ab5c65b76f2))
* **helm:** add ServiceMonitor, PrometheusRule, and PodDisruptionBudget templates ([#26](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/26)) ([#34](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/34)) ([0b0b857](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/0b0b857925a2e84a25cc187bca356a3d4932d1ac))

## [0.2.0](https://github.com/Josh-Archer/vaultwarden-eso-bridge/compare/v0.1.8...v0.2.0) (2026-08-23)


### Features

* add end-to-end ESO webhook examples and ExternalSecret samples ([#2](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/2)) ([#8](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/8)) ([4028ab4](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/4028ab433d7068bbdbf354df864c3890735157c8))
* **bridge:** harden public chart defaults and docs ([d71f08d](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/d71f08dff9ec648adafd8af50d094af0c190ad4f))
* multi-arch (amd64+arm64) bridge image publish (0.1.8) ([#17](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/17)) ([4a7c03e](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/4a7c03e8dede7682a24007e7f9ea13e53cd3c64b))
* optional HTTP cache TTL for hot secret keys ([#4](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/4)) ([#11](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/11)) ([40ca732](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/40ca732b468c74f31d9f1dd258e792bd29967dca))
* session readiness and auth refresh metrics ([#3](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/3)) ([#12](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/12)) ([d1f14ed](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/d1f14ed595861adcf8e91e4878fd87de37c9906c))


### Bug Fixes

* complete 0.1.6 session ready lock and auth bootstrap (release as 0.1.7) ([#15](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/15)) ([76becc6](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/76becc6c40511b2df408389734a9fac1294adc81))
* prefer strict token matching over silent variant expand ([#6](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/6)) ([#9](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/9)) ([65c62cf](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/65c62cfbf1eecd873c1bc3659b1a2e541eaedcf1))
* restore clean bridge 0.1.7 (session lock + parse_bool_env) ([#16](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/16)) ([e576550](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/e576550afcde0fe5d583e3d7f01b6cdb4c22dff8))
* restore parse_bool_env for BRIDGE_TOKEN_LEGACY_VARIANTS ([#14](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/14)) ([7e646c0](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/7e646c0ff33b503212a454c706f7395fd0e4737a))
* use external repo chart path in publish script ([eb1fb8f](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/eb1fb8ffd36529d73b2c245aa9282cb8bb08fefc))


### Miscellaneous Chores

* **chart:** bump vaultwarden-eso-bridge to 0.1.1 ([361436c](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/361436ce57230e8edbabf58bfc5477608049039e))
* remove pycache artifacts and add gitignore ([94eb343](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/94eb34329e8c0321219e428a0f45f2d1783f6746))


### Continuous Integration

* add Release-Please automated release pipeline ([#18](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/18)) ([#30](https://github.com/Josh-Archer/vaultwarden-eso-bridge/issues/30)) ([9c25073](https://github.com/Josh-Archer/vaultwarden-eso-bridge/commit/9c25073c65a683218b482cd8db7d216e3688a8aa))
