import fp from 'fastify-plugin'
import type { FastifyPluginAsync, FastifyRequest, FastifyReply, RouteOptions, RouteShorthandOptions, HTTPMethods } from 'fastify'

declare module 'fastify' {
  interface RouteShorthandOptions {
    allowIf?: (request: FastifyRequest) => Promise<boolean>
  }

  interface FastifyContextConfig {
    seed?: Object
  }
}

/**
 * Format: "METHOD:/path"
 * Example: "GET:/health" or "POST:/api/users"
 */
export type ZeroTrustRoute = `${HTTPMethods}:${string}`

export interface ZeroTrustOptions {
  /** Array of routes to exclude from zero-trust validation */
  excludedRoutes?: ZeroTrustRoute[]
  onMissingValidator?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>
  onValidatorDenied?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>
  onValidatorError?: (request: FastifyRequest, reply: FastifyReply, error: Error) => Promise<void>
}

const plugin: FastifyPluginAsync<ZeroTrustOptions> = async (fastify, options) => {
  const validators = new WeakMap<Object, (request: FastifyRequest) => Promise<boolean>>()
  const excludedRoutes = options.excludedRoutes || []

  // Add hook to store validator during route registration
  fastify.addHook('onRoute', (routeOptions: RouteOptions) => {
    const routePath = `${routeOptions.method}:${routeOptions.url}` as ZeroTrustRoute
    
    // Skip validator storage for excluded routes
    if (excludedRoutes.includes(routePath)) {
      return
    }

    if (routeOptions.allowIf) {
      const seed = {} // new object, new reference
      validators.set(seed, routeOptions.allowIf);
      routeOptions.config ??= {};
      routeOptions.config.seed = seed

      routeOptions.allowIf = undefined // Clean up since it's not a standard option
    }
  })

  // Add onRequest hook to implement zero-trust
  fastify.addHook('preValidation', async (request: FastifyRequest, reply: FastifyReply) => {
    const routeOptions = request.routeOptions
    const routePath = `${routeOptions.method}:${routeOptions.url}` as ZeroTrustRoute

    // Skip validation for excluded routes
    if (excludedRoutes.includes(routePath)) {
      return
    }

    const validator = request.routeOptions.config?.seed 
      ? validators.get(request.routeOptions.config.seed)
      : undefined

    if (!validator) {
      if (options.onMissingValidator) {
        return options.onMissingValidator(request, reply)
      }
      return reply.code(403).send({ error: 'Access denied by default' })
    }

    try {
      const isAllowed = await validator(request)
      if (!isAllowed) {
        if (options.onValidatorDenied) {
          return options.onValidatorDenied(request, reply)
        }
        return reply.code(403).send({ error: 'Access denied by validator' })
      }
    } catch (error) {
      if (options.onValidatorError) {
        return options.onValidatorError(request, reply, error as Error)
      }
      return reply.code(403).send({ error: 'Access validation failed' })
    }
  })
}

export default fp(plugin, {
  name: 'fastify-zero-trust',
  fastify: '5.x'
})
