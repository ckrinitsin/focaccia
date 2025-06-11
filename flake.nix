{
	description = "Focaccia: A Symbolic Tester for QEMU";

	inputs = {
		nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

		nixpkgs-qemu-60.url = "github:nixos/nixpkgs/f8f124009497b3f9908f395d2533a990feee1de8";

		flake-utils.url = "github:numtide/flake-utils";

		pyproject-nix = {
			url = "github:pyproject-nix/pyproject.nix";
			inputs.nixpkgs.follows = "nixpkgs";
		};

		uv2nix = {
			url = "github:pyproject-nix/uv2nix";
			inputs.nixpkgs.follows = "nixpkgs";
			inputs.pyproject-nix.follows = "pyproject-nix";
		};

		pyproject-build-systems = {
			url = "github:pyproject-nix/build-system-pkgs";
			inputs.uv2nix.follows = "uv2nix";
			inputs.nixpkgs.follows = "nixpkgs";
			inputs.pyproject-nix.follows = "pyproject-nix";
		};
	};

	outputs = inputs@{
		self,
		uv2nix,
		nixpkgs,
		flake-utils,
		pyproject-nix,
		pyproject-build-systems,
		...
	}:
	flake-utils.lib.eachDefaultSystem (system:
	let
		qemu-60 = inputs.nixpkgs-qemu-60.qemu;

		# Refine nixpkgs used in flake to system arch
		pkgs = import nixpkgs {
			inherit system;
		};

		musl-pkgs = import nixpkgs {
			inherit system;
			crossSystem = {
				config = "x86_64-unknown-linux-musl";
			};
		};

		# Pin Python version
		python = pkgs.python312;

		# Define workspace root and load uv workspace metadata
		workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

		# Create an overlay for Nix that includes extracted Python packages declared as dependencies
		# in uv
		overlay = workspace.mkPyprojectOverlay { sourcePreference = "wheel"; };

		# Another overlay layer for flake-specific overloads
		# This might be needed because uv does not have sufficient metadata
		# Here, uv does include metadata about build systems used by each dependency
		# Ergo we need to add a nativeBuildInput to miasm because it depends on setuptools for its
		# installation
		pyprojectOverrides = self: super: {
			miasm = super.miasm.overrideAttrs (old: {
				nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ self.setuptools ];
			});
			"python-cpuid" = super."python-cpuid".overrideAttrs (old: {
				nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ 
					self.setuptools
					pkgs.clang
				];
			});
		};

		# Build a set of Python packages
		# The call to callPackage here uses the base package set from pyproject.nix
		# We inherit the Python version to ensure that the packages have the same version
		#
		# The overrideScope here customizes the Python package set with an overlay defined by the
		# composition of three overlay functions
		pythonSet = (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).
					 overrideScope (pkgs.lib.composeManyExtensions [
						 pyproject-build-systems.overlays.default
						 overlay
						 pyprojectOverrides 
					 ]);

		 # Create a Python venv with the default dependency group
		 pythonEnv = pythonSet.mkVirtualEnv "focaccia-env" workspace.deps.default;
	in {
		# Default package just builds Focaccia
		packages.default = pythonEnv;

		# Default app is just Focaccia
		apps.default = {
			type = "app";
			program = "${self.packages.default}/bin/focaccia";
		};

		# Developer shell that includes Focaccia and QEMU
		devShells = {
			default = pkgs.mkShell {
				packages = [
					pythonEnv
					pkgs.qemu-user
					musl-pkgs.gcc
					musl-pkgs.pkg-config
					pkgs.gdb
				];
			};

			qemu-60 = pkgs.mkShell {
				packages = [
					pythonEnv
					qemu-60
					musl-pkgs.gcc
					musl-pkgs.pkg-config
					pkgs.gdb
				];
			};
		};
	});
}

