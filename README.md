# fastify-zero-trust

A zero-trust plugin for Fastify that enforces explicit access control for all routes.

## Features

- Default deny: all routes are blocked by default
- Route-level access control
- Async validation support
- TypeScript support

## Installation

```bash
npm install fastify-zero-trust
```

## Usage

```typescript
import Fastify from 'fastify'
import zeroTrust from 'fastify-zero-trust'

const fastify = Fastify()

// Register the plugin
await fastify.register(zeroTrust)

// Public route
fastify.get('/hello', {
  allowIf: async (request) => true
}, async (request, reply) => {
  return { hello: 'world' }
})

// Protected route
fastify.get('/protected', {
  allowIf: async (request) => {
    return request.headers['x-access-token'] === 'secret-token'
  }
}, async (request, reply) => {
  return { message: 'secret data' }
})

await fastify.listen({ port: 3000 })
```

## Plugin Options

You can customize error handling and exclude routes by providing options:

```typescript
await fastify.register(zeroTrust, {
  // Routes to exclude from validation (format: "METHOD:/path")
  excludedRoutes: ['GET:/health', 'GET:/metrics'],
  // Called when no validator is found for a route
  onMissingValidator: async (request, reply) => {
    reply.code(403).send({ error: 'Custom default deny message' })
  },
  // Called when a validator returns false
  onValidatorDenied: async (request, reply) => {
    reply.code(403).send({ error: 'Custom validation denied message' })
  },
  // Called when a validator throws an error
  onValidatorError: async (request, reply, error) => {
    reply.code(403).send({ error: `Validation error: ${error.message}` })
  }
})
```

## Route Configuration

The plugin adds an `allowIf` option to route definitions. This function should return a Promise<boolean>:

- Return `true` to allow access
- Return `false` to deny access
- If no `allowIf` function is provided, access is denied by default

## TypeScript Support

The plugin includes TypeScript type definitions and extends Fastify's `RouteOptions` interface.

## License

MIT
