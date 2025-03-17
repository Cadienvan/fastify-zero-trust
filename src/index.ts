import fp from 'fastify-plugin'
import type { FastifyPluginAsync, FastifyRequest, FastifyReply, RouteOptions, RouteShorthandOptions } from 'fastify'

declare module 'fastify' {
  interface RouteShorthandOptions {
    allowIf?: (request: FastifyRequest) => Promise<boolean>
  }
}

export interface ZeroTrustOptions {
  onMissingValidator?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>
  onValidatorDenied?: (request: FastifyRequest, reply: FastifyReply) => Promise<void>
  onValidatorError?: (request: FastifyRequest, reply: FastifyReply, error: Error) => Promise<void>
}

const plugin: FastifyPluginAsync<ZeroTrustOptions> = async (fastify, options) => {
  const validators = new Map<string, (request: FastifyRequest) => Promise<boolean>>()

  // Add hook to store validator during route registration
  fastify.addHook('onRoute', (routeOptions: RouteOptions) => {
    if (routeOptions.allowIf) {
      validators.set(`${routeOptions.method}:${routeOptions.url}`, routeOptions.allowIf)
      delete routeOptions.allowIf // Clean up since it's not a standard option
    }
  })

  // Add onRequest hook to implement zero-trust
  fastify.addHook('preValidation', async (request: FastifyRequest, reply: FastifyReply) => {
    const routeOptions = request.routeOptions
    const validator = validators.get(`${routeOptions.method}:${routeOptions.url}`)

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
