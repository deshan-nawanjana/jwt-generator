const PRIVATE_KEY = 'my_site_secret'

let base64Encode = txt => {
    let rep = (x, a, b) => {
        while(x.indexOf(a) > -1) { x = x.replace(a, b) }
        return x
    }
    txt = rep(txt, '+', '-')
    txt = rep(txt, '/', '_')
    txt = rep(txt, '=', '')
    return txt
}

let hash_dnjs = (txt, key) => {
    let out = ''
    let crr = 0
    Array.from(txt).forEach((t, i) => {
        let k = key[crr]
        let a = t.charCodeAt()
        let b = k.charCodeAt()
        let d = (a > b ? a - b : b - a) % 26 + 97
        out += i % 2 ? String.fromCharCode(d) : ''
        crr === key.length - 1 ? crr = 0 : crr++
    })
    return btoa(out)
}

let generateToken = (object, time, payload = {}) => {
    // header data
    let header = { alg : 'DNJS', type : 'JWT' }
    // payload data
    payload['iat'] = Date.now(),
    payload['exp'] = Date.now() + time,
    payload['obj'] = object
    // create encoded header
    let header64 = base64Encode(btoa(JSON.stringify(header)))
    // create encoded payload
    let payload64 = base64Encode(btoa(JSON.stringify(payload)))
    // create signature
    let signature = hash_dnjs(
        header64 + '.' + payload64,
        PRIVATE_KEY
    )
    // encode signature
    let signature64 = base64Encode(signature)
    // return token
    return header64 + '.' + payload64 + '.' + signature64
}

let validateToken = token => {
    // get token string and split
    if(token.indexOf('Bearer ') > -1) { token = token.substr(7) }
    let parts = token.split('.')
    // define three parts
    let header64 = parts[0]
    let payload64 = parts[1]
    let signature64 = parts[2]
    // create signature again from received header and payload
    let check = hash_dnjs(
        header64 + '.' + payload64,
        PRIVATE_KEY
    )
    // check if token decodable
    if(base64Encode(check) !== signature64) {
        return 'TOKEN_INVALID'
    }
    // get payload data if token decoded successfully
    let payload = JSON.parse(atob(payload64))
    // check token values
    if(payload['iat'] === undefined) {
        // no issued time
        return 'TOKEN_INVALID'
    } else if(payload['exp'] === undefined) {
        // no expiration time
        return 'TOKEN_INVALID'
    } else if(payload['obj'] === undefined) {
        // no data object
        return 'TOKEN_INVALID'
    } else if(payload['iat'] > Date.now() || payload['exp'] < Date.now()) {
        // expired token
        return 'TOKEN_EXPIRED'
    } else {
        // return valid token
        return payload['obj']
    }
}