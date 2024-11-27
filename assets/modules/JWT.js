// format encoded string
const format = (input, encode) => {
  // encode string if required
  if (encode) { input = window.btoa(JSON.stringify(input)) }
  // replace special characters
  input = input.replace(/\+/g, "-")
  input = input.replace(/\//g, "_")
  input = input.replace(/\=/g, "")
  // return formatted string
  return input
}

const hash = async (message, secret) => {
  // create text encoder
  const encoder = new TextEncoder()
  // encode key and message data
  const key = encoder.encode(secret)
  const data = encoder.encode(message)
  // import key from crypto
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false, ["sign"]
  )
  // generate hmac from crypto
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, data)
  // convert signature to hex format
  const hex = Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
  // return formatted hash
  return format(hex)
}

/** JWT Module */
export const JWT = class {
  /**
   * @param {string} secret Server secret
   */
  constructor(secret) {
    // store server secret
    this.secret = secret
  }
  /**
   * Generates token
   * @param {object} object Data object in payload
   * @param {number} duration Token validity duration in seconds
   * @returns 
   */
  async generate(object = {}, duration = 1800) {
    // create data object
    const data = {}
    // create current time stamp
    const time = parseInt(Date.now() / 1000)
    // assign payload props
    Object.assign(data, { iat: time })
    Object.assign(data, { exp: time + duration })
    Object.assign(data, { obj: object })
    // create encoded header
    const header = format({ alg: "HS256", type: "JWT" }, true)
    // create encoded payload
    const payload = format(data, true)
    // create signature with secret
    const signature = await hash(header + "." + payload, this.secret)
    // return generated token
    return `${header}.${payload}.${signature}`
  }
  /**
   * Validates token
   * @param {string} token 
   */
  async validate(token) {
    // split token into parts
    const parts = token.split(".")
    // return if invalid token
    if (parts.length !== 3) { return "TOKEN_INVALID" }
    // get token parts
    const header = parts[0]
    const payload = parts[1]
    // regenerate signature from header and payload
    const signature = await hash(`${header}.${payload}`, this.secret)
    // invalid token if signature mismatched
    if (signature !== parts[2]) { return "TOKEN_INVALID" }
    // decode and parse payload data
    const data = JSON.parse(window.atob(payload))
    // invalid token if no issued time
    if (!Object.hasOwn(data, "iat")) { return "TOKEN_INVALID" }
    // invalid token if no expiration time
    if (!Object.hasOwn(data, "exp")) { return "TOKEN_INVALID" }
    // invalid token if no data object
    if (!Object.hasOwn(data, "obj")) { return "TOKEN_INVALID" }
    // get current time stamp
    const time = parseInt(Date.now() / 1000)
    // invalid token if invalid issued time
    if (data.iat > time) { return "TOKEN_INVALID" }
    // expired token if passed expired time
    if (data.exp < time) { return "TOKEN_EXPIRED" }
    // return valid token data
    return data.obj
  }
}
