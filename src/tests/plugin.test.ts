import { test, describe } from 'node:test'
import assert from 'node:assert'
import Fastify from 'fastify'
import zeroTrust from '../index'

describe('fastify-zero-trust', async () => {
  test('should deny access by default', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust)

    fastify.get('/test', async () => ({ hello: 'world' }))

    const response = await fastify.inject({
      method: 'GET',
      url: '/test'
    })

    assert.strictEqual(response.statusCode, 403)
    assert.deepStrictEqual(JSON.parse(response.payload), { error: 'Access denied by default' })
  })

  test('should allow access when validator returns true', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust)

    fastify.get('/test', {
      allowIf: async () => true
    }, async () => ({ hello: 'world' }))

    const response = await fastify.inject({
      method: 'GET',
      url: '/test'
    })

    assert.strictEqual(response.statusCode, 200)
    assert.deepStrictEqual(JSON.parse(response.payload), { hello: 'world' })
  })

  test('should deny access when validator returns false', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust)

    fastify.get('/test', {
      allowIf: async () => false
    }, async () => ({ hello: 'world' }))

    const response = await fastify.inject({
      method: 'GET',
      url: '/test'
    })

    assert.strictEqual(response.statusCode, 403)
    assert.deepStrictEqual(JSON.parse(response.payload), { error: 'Access denied by validator' })
  })

  test('should handle validator throwing an error', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust)

    fastify.get('/test', {
      allowIf: async () => {
        throw new Error('Validation failed')
      }
    }, async () => ({ hello: 'world' }))

    const response = await fastify.inject({
      method: 'GET',
      url: '/test'
    })

    assert.strictEqual(response.statusCode, 403)
    assert.deepStrictEqual(JSON.parse(response.payload), { error: 'Access validation failed' })
  })

  test('should work with different HTTP methods', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust)

    fastify.post('/test', {
      allowIf: async () => true
    }, async () => ({ success: true }))

    const response = await fastify.inject({
      method: 'POST',
      url: '/test'
    })

    assert.strictEqual(response.statusCode, 200)
    assert.deepStrictEqual(JSON.parse(response.payload), { success: true })
  })

  test('should have access to request in validator', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust)

    fastify.get('/test', {
      allowIf: async (request) => {
        return request.headers['x-token'] === 'valid-token'
      }
    }, async () => ({ success: true }))

    const responseWithoutToken = await fastify.inject({
      method: 'GET',
      url: '/test'
    })

    assert.strictEqual(responseWithoutToken.statusCode, 403)

    const responseWithToken = await fastify.inject({
      method: 'GET',
      url: '/test',
      headers: {
        'x-token': 'valid-token'
      }
    })

    assert.strictEqual(responseWithToken.statusCode, 200)
  })

  test('should use custom onMissingValidator handler', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust, {
      onMissingValidator: async (request, reply) => {
        reply.code(401).send({ error: 'Custom missing validator message' })
      }
    })

    fastify.get('/test', async () => ({ hello: 'world' }))

    const response = await fastify.inject({
      method: 'GET',
      url: '/test'
    })

    assert.strictEqual(response.statusCode, 401)
    assert.deepStrictEqual(JSON.parse(response.payload), { error: 'Custom missing validator message' })
  })

  test('should use custom onValidatorDenied handler', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust, {
      onValidatorDenied: async (request, reply) => {
        reply.code(401).send({ error: 'Custom validator denied message' })
      }
    })

    fastify.get('/test', {
      allowIf: async () => false
    }, async () => ({ hello: 'world' }))

    const response = await fastify.inject({
      method: 'GET',
      url: '/test'
    })

    assert.strictEqual(response.statusCode, 401)
    assert.deepStrictEqual(JSON.parse(response.payload), { error: 'Custom validator denied message' })
  })

  test('should use custom onValidatorError handler', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust, {
      onValidatorError: async (request, reply, error) => {
        reply.code(500).send({ error: `Custom error: ${error.message}` })
      }
    })

    fastify.get('/test', {
      allowIf: async () => {
        throw new Error('Test error')
      }
    }, async () => ({ hello: 'world' }))

    const response = await fastify.inject({
      method: 'GET',
      url: '/test'
    })

    assert.strictEqual(response.statusCode, 500)
    assert.deepStrictEqual(JSON.parse(response.payload), { error: 'Custom error: Test error' })
  })

  test('should have access to POST data in validator', async () => {
    const fastify = Fastify()
    await fastify.register(zeroTrust)

    fastify.post('/test', {
      allowIf: async (request) => {
        const body = request.body as { token?: string }
        return body.token === 'secret-token'
      }
    }, async () => ({ success: true }))

    const responseWithoutToken = await fastify.inject({
      method: 'POST',
      url: '/test',
      payload: {}
    })

    assert.strictEqual(responseWithoutToken.statusCode, 403)

    const responseWithToken = await fastify.inject({
      method: 'POST',
      url: '/test',
      payload: {
        token: 'secret-token'
      }
    })

    assert.strictEqual(responseWithToken.statusCode, 200)
    assert.deepStrictEqual(JSON.parse(responseWithToken.payload), { success: true })
  })

})
