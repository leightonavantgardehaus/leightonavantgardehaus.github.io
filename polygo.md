



**This is a proof-of-concept / learning playground** — **not production-ready**, **no real secrets** included, and **intentionally simplified** (placeholder inference, no full NLP/ML).

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