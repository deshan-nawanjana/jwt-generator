import { JWT } from "./assets/modules/JWT.js"

// create jwt module
const module = new JWT("no-secret")

new Vue({
  el: "#app",
  data: {
    ready: false,
    mode: "generate",
    secret: "",
    data: "",
    duration: "",
    token: "",
    status: "",
    error: ""
  },
  methods: {
    // method to switch mode
    switchMode(mode) {
      // clear app data
      this.secret = ""
      this.data = ""
      this.duration = ""
      this.token = ""
      this.status = ""
      this.error = ""
      // update mode
      this.mode = mode
    },
    // method to select text
    selectText(event) {
      // focus on element
      event.target.focus()
      // select element text
      event.target.select()
    },
    // method to generate token
    async generate() {
      // clear error message
      this.error = ""
      // clear current token
      this.token = ""
      // randomize secret if not given
      if (!this.secret) {
        this.secret = window.crypto.randomUUID()
      }
      // assign object if not given
      if (!this.data) {
        this.data = JSON.stringify({
          username: "john.smith@example.com",
          role: "admin"
        })
      }
      // assign duration if not given
      if (!this.duration) {
        this.duration = 60 * 30
      }
      try {
        // set token secret on module
        module.secret = this.secret
        // parse data object
        const object = JSON.parse(this.data)
        // parse duration
        const duration = parseInt(this.duration)
        // check duration
        if (isNaN(duration)) {
          // set duration error
          this.error = "Invalid duration"
        } else {
          // generate token
          this.token = await module.generate(object, duration)
        }
      } catch (error) {
        // set error
        this.error = error.message.split("(")[0]
      }
    },
    // method to decode token
    decode() {
      // clear error message
      this.error = ""
      // clear data
      this.data = ""
      // get token string
      const token = this.token
      // split token parts
      const parts = token.split(".")
      // check token input
      if (!token) {
        this.error = "Token is required"
      } else if (parts.length !== 3) {
        this.error = "Token is invalid"
      } else {
        try {
          // decode payload segment
          const payload = window.atob(parts[1])
          // decode payload
          this.data = JSON.stringify(JSON.parse(payload))
        } catch (error) {
          // set error
          this.error = error.message.split("(")[0]
        }
      }
    },
    // method to validate token
    async validate() {
      // clear error message
      this.error = ""
      // clear status
      this.status = ""
      // clear data
      this.data = ""
      // get token and strings
      const token = this.token
      const secret = this.secret
      // check strings
      if (!token) {
        this.error = "Token is required"
      } else if (!secret) {
        this.error = "Secret is required"
      } else {
        try {
          // set token secret on module
          module.secret = secret
          // validate token
          const output = await module.validate(token)
          // check output
          if (typeof output === "string") {
            // set invalid status
            this.status = output
          } else {
            // set valid status
            this.status = "TOKEN_VALID"
            // set output data
            this.data = JSON.stringify(output)
          }
        } catch (error) {
          // set error
          this.error = error.message.split("(")[0]
        }
      }

    }
  },
  mounted() {
    // appear interface on mount
    setTimeout(() => this.ready = true, 200)
  }
})
