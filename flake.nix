{
  description = "CoreDNS built with the blockpolicy plugin from this repo";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      # The blockpolicy plugin lives at ./blockpolicy; its module root is this repo.
      blockpolicyMod = "github.com/kusold/coredns-blockpolicy/blockpolicy";
      blockpolicyParent = "github.com/kusold/coredns-blockpolicy";
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          lib = pkgs.lib;
        in
        {
          default = self.packages.${system}.coredns;
          coredns =
            (pkgs.coredns.override {
              # We don't use nixpkgs' externalPlugins here (it would `go get` the
              # plugin from the network at a pinned commit). Instead we override the
              # go-modules phase below to wire in the *local* checkout, so the flake
              # always builds the current code.
              externalPlugins = [ ];
              # Hash of the vendored coredns+blockpolicy modules. When dependencies
              # change, `nix build` prints the correct value on mismatch.
              vendorHash = "sha256-b1sZqyJNU7FfXDAvRGQVNhsnnWy2jHayPC2FeMz4Mfw=";
            }).overrideAttrs (
              previousAttrs:
              {
                # Replace the go-modules build phase: insert the plugin into plugin.cfg
                # (after `cache`, per the blockpolicy README ordering) and source it from
                # this repo via a go.mod replace instead of `go get`.
                passthru = (previousAttrs.passthru or { }) // {
                  overrideModAttrs =
                    _finalAttrs: _previousModAttrs:
                    {
                      preBuild = ''
                        cp plugin.cfg plugin.cfg.orig
                        if ! grep -q '^cache:' plugin.cfg; then
                          echo 'Failed to insert blockpolicy after cache: cache is not in plugin.cfg' >&2
                          exit 1
                        fi
                        sed -i '/^cache:/a blockpolicy:${blockpolicyMod}' plugin.cfg
                        diff -u plugin.cfg.orig plugin.cfg || true
                        # Copy the local plugin source into the build dir and point a
                        # *relative* go.mod replace at it. A relative path (rather than
                        # the absolute /nix/store path) keeps the fixed-output go-modules
                        # derivation free of store-path references, which nix requires.
                        cp -r "${self}/." ./blockpolicy-src
                        go mod edit -replace ${blockpolicyParent}=./blockpolicy-src
                        GOFLAGS=''${GOFLAGS//-mod=vendor/} CC= GOOS= GOARCH= go generate
                        go mod tidy
                      '';
                      postBuild = ''
                        mv -t vendor go.mod go.sum plugin.cfg
                      '';
                    };
                };
              }
            );
        }
      );
    };
}
