
**Experimental polyglo prototype** (.NET + Go + gRPC) demonstrating **attribute-augmented federation** using OAuth 2.0 / OpenID Connect.

- Microsoft Entra ID (enterprise signals, risk/device compliance)
- LinkedIn (professional profile inference)
- ORCID (researcher affiliations)

Merges/enriches attributes for ABAC/zero-trust style decisions in coalition or DDIL scenarios.

**This is a proof-of-concept / learning playground** — **not production-ready**, **no real secrets** included, and **intentionally simplified** (placeholder inference, no full NLP/ML).

## Features
- OIDC federation via Entra ID as primary IdP
- gRPC-based augmentation service in Go (LinkedIn/ORCID processing + caching ideas)
- Attribute merging in .NET orchestrator
- Extensible for "fusion kernel" experiments (e.g., deriving DoD-style attrs from signals)

## Architecture
- **.NET 9 (ASP.NET Core)**: Handles auth, Graph API calls, policy/claims merging
- **Go**: Lightweight augmentation (profile parsing, symbolic mapping)
- **gRPC + Protobuf**: Clean inter-service contract

See [docs/architecture.md](docs/architecture.md) for diagram (add one via draw.io if you want!).

## Quick Start

### Prerequisites
- .NET 9 SDK
- Go 1.23+
- protoc compiler

### Setup
1. Clone & generate protobufs:
   ```bash
   git clone https://github.com/YOURUSERNAME/icam-attribute-augmentation-demo.git
   cd icam-attribute-augmentation-demo
   cd proto
   protoc --go_out=../src/go/augment-service --go-grpc_out=../src/go/augment-service augment.proto