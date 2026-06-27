# Stage 1: Build the application
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency graphs
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -o ticket-system main.go

# Stage 2: Create the final minimal image
FROM alpine:latest

WORKDIR /root/

# Copy the pre-built binary file from the previous stage
COPY --from=builder /app/ticket-system .

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./ticket-system"]