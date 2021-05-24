/*
    try {
      let notarisation = 'AFAFA'
      let fileHash

      // Convert FileReader ArrayBuffer to WordArray first
      const resultWordArray = CryptoJS.lib.WordArray.create(reader.result)

      if (hashFunction === 'SHA256') {
        fileHash = CryptoJS.SHA256(resultWordArray).toString(CryptoJS.enc.Hex)
        notarisation = notarisation + '2' + fileHash
      }

      // Convert free form text to hex
      const additionalTextBytes = stringToBytes(additionalText)
      const additionalTextHex = bytesToHex(additionalTextBytes)

      // Construct final hex string for notarisation
      const finalNotarisation = notarisation + additionalTextHex

      // Set message field to document notarisation string
      document.getElementById('message').value = finalNotarisation

      // Set the filename in local store for later display in UI
      Session.set('notaryDocumentName', notaryDocument.name)
      Session.set('notaryAdditionalText', additionalText)
      Session.set('notaryHashFunction', hashFunction)
      Session.set('notaryFileHash', fileHash)

      // Create a message txn with this data
      createMessageTxn()
    } catch (err) {
      console.log(err)
      // Invalid file format
      Session.set('documentNotarisationError', 'Unable to open Document - Are you sure you selected a document to notarise?')
      $('#documentNotarisationFailed').show()
      $('#generating').hide()
    }
*/

/* global QRLLIB */
/* eslint new-cap: 0 */
const { Command, flags } = require('@oclif/command')
const { white, red } = require('kleur')
const ora = require('ora')
// const moment = require('moment')
const fs = require('fs')
const validateQrlAddress = require('@theqrl/validate-qrl-address')
const aes256 = require('aes256')
const { cli } = require('cli-ux')
const { QRLLIBmodule } = require('qrllib/build/offline-libjsqrl') // eslint-disable-line no-unused-vars
// const { BigNumber } = require('bignumber.js')
const helpers = require('@theqrl/explorer-helpers')

const Qrlnode = require('../functions/grpc')

let QRLLIBLoaded = false

const waitForQRLLIB = (callBack) => {
  setTimeout(() => {
    // Test the QRLLIB object has the str2bin function.
    // This is sufficient to tell us QRLLIB has loaded.
    if (typeof QRLLIB.str2bin === 'function' && QRLLIBLoaded === true) {
      callBack()
    } else {
      QRLLIBLoaded = true
      return waitForQRLLIB(callBack)
    }
    return false
  }, 50)
}

function string2Bin(str) {
  const result = [];
/* eslint no-plusplus: ["error", { "allowForLoopAfterthoughts": true }] */
  for (let i = 0; i < str.length; i++) {
    result.push(str.charCodeAt(i));
  }
  return result;
}

const toUint8Vector = (arr) => {
  const vec = new QRLLIB.Uint8Vector()
  for (let i = 0; i < arr.length; i += 1) {
    vec.push_back(arr[i])
  }
  return vec
}


// Convert bytes to hex
function bytesToHex(byteArray) {
  return [...byteArray]
    /* eslint-disable */
    .map((byte) => {
      return ('00' + (byte & 0xff).toString(16)).slice(-2)
    })
    /* eslint-enable */
    .join('')
}

// Concatenates multiple typed arrays into one.
function concatenateTypedArrays(resultConstructor, ...arrays) {
  /* eslint-disable */
  let totalLength = 0
  for (let arr of arrays) {
    totalLength += arr.length
  }
  const result = new resultConstructor(totalLength)
  let offset = 0
  for (let arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  /* eslint-enable */
  return result
}

// Convert Binary object to Bytes
function binaryToBytes(convertMe) {
  const thisBytes = new Uint8Array(convertMe.size())
  for (let i = 0; i < convertMe.size(); i += 1) {
    thisBytes[i] = convertMe.get(i)
  }
  return thisBytes
}

// Take input and convert to unsigned uint64 bigendian bytes
function toBigendianUint64BytesUnsigned(i, bufferResponse = false) {
  let input = i
  if (!Number.isInteger(input)) {
    input = parseInt(input, 10)
  }

  const byteArray = [0, 0, 0, 0, 0, 0, 0, 0]

  for (let index = 0; index < byteArray.length; index += 1) {
    const byte = input & 0xff // eslint-disable-line no-bitwise
    byteArray[index] = byte
    input = (input - byte) / 256
  }

  byteArray.reverse()

  if (bufferResponse === true) {
    const result = Buffer.from(byteArray)
    return result
  }
  const result = new Uint8Array(byteArray)
  return result
}

const openWalletFile = (path) => {
  const contents = fs.readFileSync(path)
  return JSON.parse(contents)[0]
}

function byteCount(s) {
    return encodeURI(s).split(/%..|./).length - 1;
}





// check if file is empty
function isFileEmpty(fileName, ignoreWhitespace=true) {
  return new Promise((resolve, reject) => {
    fs.readFile(fileName, (err, data) => {
      if( err ) {
        reject(err);
        return;
      }
      resolve((!ignoreWhitespace && data.length === 0) || (ignoreWhitespace && !!String(data).match(/^\s*$/)))
    });
  })
}



const openFile = (path) => {
  const contents = fs.readFileSync(path)
  return JSON.parse(contents)
}








class Notarise extends Command {
  async run() {
    const { args, flags } = this.parse(Notarise)
    // network stuff, defaults to mainnet
    let grpcEndpoint = 'mainnet-1.automated.theqrl.org:19009'
    let network = 'Mainnet'
    if (flags.grpc) {
      grpcEndpoint = flags.grpc
      network = `Custom GRPC endpoint: [${flags.grpc}]`
    }
    if (flags.testnet) {
      grpcEndpoint = 'testnet-1.automated.theqrl.org:19009'
      network = 'Testnet'
    }
    if (flags.mainnet) {
      grpcEndpoint = 'mainnet-1.automated.theqrl.org:19009'
      network = 'Mainnet'
    }
    this.log(white().bgBlue(network))
    // the data to notarise here, can be a file submitted (path) or a string passed on cli
    let notarialData
    let messageData
    let notarisation = 'AFAFA'
    let fileHash



    if (flags.sha2256) {


      fileHash = CryptoJS.SHA256(resultWordArray).toString(CryptoJS.enc.Hex)
      notarisation = notarisation + '2' + fileHash


    }

    const spinner = ora({ text: 'Notarising Data...\n', }).start()
    // is it a file?
    if (fs.existsSync(args.notarialData)) {
      // file submitted, is file empty?
      isFileEmpty(args.notarialData).then( (isEmpty) => {
        if (isEmpty) {
          spinner.fail('File is empty...')
          this.exit(1)
        }
      })
      try{
        notarialData = openFile(args.notarialData)
      }
      catch (e) {
        spinner.fail('Unable to open file...')
        this.exit(1)
      }
    }
    // not a file, is there data here?
    else {
      if (typeof args.notarialData === 'undefined' || args.notarialData === null) {
        // variable is undefined or null
        spinner.fail('No data defined...')
        this.exit(1)
      }
      notarialData = args.notarialData.toString()
    }
    spinner.succeed(`notarial data recieved ${notarialData}`)
    // additional data to send with the notary - user defined
    if (flags.message) {
      // message data
      // check size of message MAX 80 bytes
      messageData = flags.message.toString()
      spinner.succeed(`messageData length ${messageData.length}`)
      if (messageData.length > 45) {
        spinner.fail(`Message cannot be longer than 45 characters...`)
        this.exit(1)
      }
      spinner.succeed(`additional message text recieved: ${messageData}`)
      // const messageBytes = string2Bin(flags.message)
      // const messageLength = byteCount(messageBytes)
    }
   



    // get wallet private details for transaction
    if (!flags.wallet && !flags.hexseed) {
      this.log(`${red('⨉')} Unable to notarise: no wallet json file or hexseed specified`)
      this.exit(1)
    }
    // wallet functions
    let hexseed = ''
    let address = ''
    // open wallet file
    if (flags.wallet) {
      let isValidFile = false
      const walletJson = openWalletFile(flags.wallet)
      try {
        if (walletJson.encrypted === false) {
          isValidFile = true
          address = walletJson.address
          hexseed = walletJson.hexseed
        }
        if (walletJson.encrypted === true) {
          let password = ''
          if (flags.password) {
            password = flags.password
          } 
          else {
            password = await cli.prompt('Enter password for wallet file', { type: 'hide' })
          }
          address = aes256.decrypt(password, walletJson.address)
          hexseed = aes256.decrypt(password, walletJson.hexseed)
          if (validateQrlAddress.hexString(address).result) {
            isValidFile = true
          } 
          else {
            this.log(`${red('⨉')} Unable to open wallet file: invalid password`)
            this.exit(1)
          }
        }
      } catch (error) {
        isValidFile = false
      }
      if (!isValidFile) {
        this.log(`${red('⨉')} Unable to open wallet file: invalid wallet file`)
        this.exit(1)
      }
      if (!flags.otsindex ) {
        this.log(`${red('⨉')} no OTS index given`)
        this.exit(1)
      }
    }
    // open from hexseed OR MNEMONIC
    if (flags.hexseed) {
      // reconstruct XMSS from hexseed
      hexseed = flags.hexseed
      // sanity checks on this parameter
      if (hexseed.match(' ') === null) {
        // hexseed: correct length?
        if (hexseed.length !== 102) {
          this.log(`${red('⨉')} Hexseed invalid: too short`)
          this.exit(1)
        }
      } else {
        // mnemonic: correct number of words?
        // eslint-disable-next-line no-lonely-if
        if (hexseed.split(' ').length !== 34) {
          this.log(`${red('⨉')} Mnemonic phrase invalid: too short`)
          this.exit(1)
        }
      }
      if (!flags.otsindex ) {
        this.log(`${red('⨉')} no OTS index given`)
        this.exit(1)
      }
    }
    // check ots for valid entry
    if (flags.otsindex) {
      const passedOts = parseInt(flags.otsindex, 10)
      if (!passedOts && passedOts !== 0) {
        this.log(`${red('⨉')} OTS key is invalid`)
        this.exit(1)
      }
    }
    // set the fee to default or flag
    let fee = 0 // default fee 0 Shor
    if (flags.fee) {
      const passedFee = parseInt(flags.fee, 10)
      if (passedFee) {
        fee = passedFee
      } else {
        this.log(`${red('⨉')} Fee is invalid`)
        this.exit(1)
      }
    }

    waitForQRLLIB(async () => {
      let XMSS_OBJECT
      if (hexseed.match(' ') === null) {
        XMSS_OBJECT = await new QRLLIB.Xmss.fromHexSeed(hexseed)
      } 
      else {
        XMSS_OBJECT = await new QRLLIB.Xmss.fromMnemonic(hexseed)
      }
      const xmssPK = Buffer.from(XMSS_OBJECT.getPK(), 'hex')
      spinner.succeed('xmssPK returned...')
      const Qrlnetwork = await new Qrlnode(grpcEndpoint)
      await Qrlnetwork.connect()
      
      // verify we have connected and try again if not
      let i = 0
      const count = 5
      while (Qrlnetwork.connection === false && i < count) {
        spinner.succeed(`retry connection attempt: ${i}...`)
        // eslint-disable-next-line no-await-in-loop
        await Qrlnetwork.connect()
        // eslint-disable-next-line no-plusplus
        i++
      }



      const request = {
        master_addr: Buffer.from('', 'hex'),
        message: messageBytes,
        addr_to: thisAddress,
        fee,
        xmss_pk: xmssPK,
      }
      const message = await Qrlnetwork.api('GetMessageTxn', request)

      const spinner3 = ora({ text: 'Signing transaction...' }).start()

      const concatenatedArrays = concatenateTypedArrays(
        Uint8Array,
        toBigendianUint64BytesUnsigned(message.extended_transaction_unsigned.tx.fee), // fee
        messageBytes,
        thisAddress,
      )

      // Convert Uint8Array to VectorUChar
      const hashableBytes = toUint8Vector(concatenatedArrays)

      // Create sha256 sum of concatenated array
      const shaSum = QRLLIB.sha2_256(hashableBytes)

      XMSS_OBJECT.setIndex(parseInt(flags.otsindex, 10))
      const signature = binaryToBytes(XMSS_OBJECT.sign(shaSum))

      // Calculate transaction hash
      const txnHashConcat = concatenateTypedArrays(Uint8Array, binaryToBytes(shaSum), signature, xmssPK)
      // tx hash bytes..
      const txnHashableBytes = toUint8Vector(txnHashConcat)
      // get the transaction hash
      const txnHash = QRLLIB.bin2hstr(QRLLIB.sha2_256(txnHashableBytes))
      spinner3.succeed(`Transaction signed with OTS key ${flags.otsindex}. (nodes will reject this transaction if key reuse is detected)`)
      const spinner4 = ora({ text: 'Pushing transaction to node...' }).start()
      // transaction sig and pub key into buffer
      message.extended_transaction_unsigned.tx.signature = Buffer.from(signature)
      message.extended_transaction_unsigned.tx.public_key = Buffer.from(xmssPK) // eslint-disable-line camelcase
      const pushTransactionReq = {
        transaction_signed: message.extended_transaction_unsigned.tx, // eslint-disable-line camelcase
      }
      // push the transaction to the network
      const response = await Qrlnetwork.api('PushTransaction', pushTransactionReq)
      if (response.error_code && response.error_code !== 'SUBMITTED') {
        let errorMessage = 'unknown error'
        if (response.error_code) {
          errorMessage = `Unable send push transaction [error: ${response.error_description}`
        } else {
          errorMessage = `Node rejected signed message: has OTS key ${flags.otsindex} been reused?`
        }
        spinner4.fail(`${errorMessage}]`)
        this.exit(1)
      }
      const pushTransactionRes = JSON.stringify(response.tx_hash)
      const txhash = JSON.parse(pushTransactionRes)
      if (txnHash === bytesToHex(txhash.data)) {
        spinner4.succeed(`Transaction submitted to node: transaction ID: ${bytesToHex(txhash.data)}`)
        
        // return link to explorer
        if (network === 'Mainnet') {
          spinner3.succeed(`https://explorer.theqrl.org/tx/${bytesToHex(txhash.data)}`)
        }
        else if (network === 'Testnet') {
          spinner3.succeed(`https://testnet-explorer.theqrl.org/tx/${bytesToHex(txhash.data)}`)
        }
        // this.exit(0)
      } 
      else {
        spinner4.fail(`Node transaction hash ${bytesToHex(txhash.data)} does not match`)
        this.exit(1)
      }
    })
  }
}

Notarise.description = `Send up to 80 byte message on the network

Message can be sent to a recipient with the (-r) flag
You can select either (-m) mainnet or (-t) testnet

Advanced: you can use a custom defined node to query for status. Use the (-g) grpc endpoint.
`

Notarise.args = [
   {
     name: 'notarialData',
     description: 'Data to notarise',
     required: true,
   },
 ]

Notarise.flags = {

  testnet: flags.boolean({
    char: 't',
    default: false,
    description: 'queries testnet for the OTS state'
  }),

  mainnet: flags.boolean({
    char: 'm',
    default: false,
    description: 'queries mainnet for the OTS state'
  }),

  grpc: flags.string({
    char: 'g',
    required: false,
    description: 'advanced: grpc endpoint (for devnet/custom QRL network deployments)',
  }),

  message: flags.string({
    char: 'M',
    default: false,
    description: 'Additional Message data to send (max 45 char)'
  }),

  sha2256: flags.boolean({
    char: '1',
    default: false,
    description: '(default) Use SHA2-256 hashing mechanism'
  }),
  shake128: flags.boolean({
    char: '2',
    default: false,
    description: 'Use SHAKE-128 hashing mechanism'
  }),
  shake256: flags.boolean({
    char: '3',
    default: false,
    description: 'Use SHAKE-256 hashing mechanism'
  }),





  wallet: flags.string({
    char: 'w',
    required: false,
    description: 'JSON (w)allet file message will be sent from',
  }),

 password: flags.string({
    char: 'p',
    required: false,
    description: 'Encrypted QRL wallet file (p)assword'
  }),

  hexseed: flags.string({
    char: 's',
    required: false,
    description: 'Secret hex(s)eed/mnemonic of address message should be sent from',
  }),

  // recipient: flags.string({
    // char: 'r',
    // required: false,
    // description: 'QRL address of recipient'
  // }),

  fee: flags.string({
    char: 'f',
    required: false,
    description: 'QRL (f)ee for transaction in Shor (defaults to 100 Shor)'
  }),

  otsindex: flags.string({ 
    char: 'i',
    required: false,
    description: 'Unused OTS key (i)ndex for message transaction' 
  }),
}

module.exports = { Notarise }
