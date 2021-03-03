/* global QRLLIB */
/* eslint new-cap: 0 */
const { Command, flags } = require('@oclif/command')
const { white, red } = require('kleur')
const ora = require('ora')
const fs = require('fs')
const validateQrlAddress = require('@theqrl/validate-qrl-address')
const aes256 = require('aes256')
const { cli } = require('cli-ux')
const { QRLLIBmodule } = require('qrllib/build/offline-libjsqrl') // eslint-disable-line no-unused-vars
const CryptoJS = require("crypto-js");
const clihelpers = require('../functions/cli-helpers')
const Qrlnode = require('../functions/grpc')

const openNotarisationFile = (path) => {
  const contents = fs.readFileSync(path)
  return contents
}

class Notarise extends Command {
  async run() {
    const { args, flags } = this.parse(Notarise)
    // network stuff, defaults to mainnet
    let grpcEndpoint = clihelpers.mainnetNode.toString()
    let network = 'Mainnet'

    if (flags.grpc) {
      grpcEndpoint = flags.grpc
      network = `Custom GRPC endpoint: [${flags.grpc}]`
    }
    if (flags.testnet) {
      grpcEndpoint = clihelpers.testnetNode.toString()
      network = 'Testnet'
    }
    if (flags.mainnet) {
      grpcEndpoint = clihelpers.mainnetNode.toString()
      network = 'Mainnet'
    }
    
    this.log(white().bgBlue(network))
    // the data to notarise here, can be a file submitted (path) or a string passed on cli
    const spinner = ora({ text: 'Notarising Data...\n', }).start()
    let notarialData
    let messageData
    let messageHex
    let notarisation = 'AFAFA'

    // is it a file?
    if (fs.existsSync(args.notarialData)) {
      spinner.succeed(`File found: ${args.notarialData} = ${fs.existsSync(args.notarialData)}`)
      // file submitted, is file empty?
      clihelpers.isFileEmpty(args.notarialData).then( (isEmpty) => {
        if (isEmpty) {
          spinner.fail('File is empty...')
          this.exit(1)
        }
      })
      try{
        notarialData = openNotarisationFile(args.notarialData)
        notarialData = Buffer.from(openNotarisationFile(args.notarialData), 'hex')
      }
      catch (e) {
        spinner.fail(`Unable to open file: ${e}`)
        this.exit(1)
      }
    }
    else {
      spinner.fail('Requires a file to notarise...')
      this.exit(1)
    }
    // Convert notarial Data to WordArray
    const resultWordArray = CryptoJS.lib.WordArray.create(notarialData)
    // sha256 hash the file, output hex
    const notarialHash = CryptoJS.SHA256(resultWordArray).toString(CryptoJS.enc.Hex)
    // add message type for notarisation, (2) and the hash from the file
    notarisation += `2${notarialHash}`
    spinner.succeed(`notarisation: ${notarisation}`)
    // additional data to send with the notary - user defined
    if (flags.message) {
      messageData = flags.message.toString()
      if (messageData.length > 45) {
        spinner.fail(`Message cannot be longer than 45 characters...`)
        this.exit(1)
      }
      spinner.succeed(`Message data recieved: ${messageData}`)
      // Convert string to hex to append to the hash
      const messageDataBytes = clihelpers.stringToBytes(messageData)
      messageHex = clihelpers.bytesToHex(messageDataBytes)
      // Construct final hex string for notarisation appending message hex
      notarisation += messageHex
    }
    spinner.succeed(`final notarisation hex: ${notarisation}`)
    // get wallet private details for transaction
    if (!flags.wallet && !flags.hexseed) {
      spinner.fail(`Unable to notarise: no wallet json file or hexseed specified`)
      this.exit(1)
    }
    // wallet functions
    let hexseed
    let address
    // open wallet file
    if (flags.wallet) {
      let isValidFile = false
      const walletJson = clihelpers.openWalletFile(flags.wallet)
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
            spinner.fail(`Unable to open wallet file: invalid password`)
            this.exit(1)
          }
        }
      }
      catch (error) {
        isValidFile = false
      }
      if (!isValidFile) {
        spinner.fail(`Unable to open wallet file: invalid wallet file`)
        this.exit(1)
      }
      if (!flags.otsindex ) {
        spinner.fail(`no OTS index given`)
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
          spinner.fail(`${red('⨉')} Hexseed invalid: too short`)
          this.exit(1)
        }
      } else {
        // mnemonic: correct number of words?
        // eslint-disable-next-line no-lonely-if
        if (hexseed.split(' ').length !== 34) {
          spinner.fail(`${red('⨉')} Mnemonic phrase invalid: too short`)
          this.exit(1)
        }
      }
      if (!flags.otsindex ) {
        spinner.fail(`${red('⨉')} no OTS index given`)
        this.exit(1)
      }
    }
    // check ots for valid entry
    if (flags.otsindex) {
      const passedOts = parseInt(flags.otsindex, 10)
      if (!passedOts && passedOts !== 0) {
        spinner.fail(`${red('⨉')} OTS key is invalid`)
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
        spinner.fail(`${red('⨉')} Fee is invalid`)
        this.exit(1)
      }
    }

    // sign and send transaction
    clihelpers.waitForQRLLIB(async () => {
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
      // get message hex into bytes for transaction
      const messageBytes = Buffer.from(notarisation, 'hex')
      const request = {
        master_addr: Buffer.from('', 'hex'),
        message: messageBytes,
        fee,
        xmss_pk: xmssPK,
      }
      // send the message transaction with the notarise encoding to the node
      const message = await Qrlnetwork.api('GetMessageTxn', request)

      const spinner3 = ora({ text: 'Signing transaction...' }).start()

      const concatenatedArrays = clihelpers.concatenateTypedArrays(
        Uint8Array,
        clihelpers.toBigendianUint64BytesUnsigned(message.extended_transaction_unsigned.tx.fee), // fee
        messageBytes,
      )
      // Convert Uint8Array to VectorUChar
      const hashableBytes = clihelpers.toUint8Vector(concatenatedArrays)
      // Create sha256 sum of concatenated array
      const shaSum = QRLLIB.sha2_256(hashableBytes)
      XMSS_OBJECT.setIndex(parseInt(flags.otsindex, 10))
      const signature = clihelpers.binaryToBytes(XMSS_OBJECT.sign(shaSum))
      // Calculate transaction hash
      const txnHashConcat = clihelpers.concatenateTypedArrays(Uint8Array, clihelpers.binaryToBytes(shaSum), signature, xmssPK)
      // tx hash bytes..
      const txnHashableBytes = clihelpers.toUint8Vector(txnHashConcat)
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
      if (txnHash === clihelpers.bytesToHex(txhash.data)) {
        spinner4.succeed(`Transaction submitted to node: transaction ID: ${clihelpers.bytesToHex(txhash.data)}`)
        
        // return link to explorer
        if (network === 'Mainnet') {
          spinner3.succeed(`https://explorer.theqrl.org/tx/${clihelpers.bytesToHex(txhash.data)}`)
        }
        else if (network === 'Testnet') {
          spinner3.succeed(`https://testnet-explorer.theqrl.org/tx/${clihelpers.bytesToHex(txhash.data)}`)
        }
        // this.exit(0)
      } 
      else {
        spinner4.fail(`Node transaction hash ${clihelpers.bytesToHex(txhash.data)} does not match`)
        this.exit(1)
      }
    })
  }
}

Notarise.description = `Notarise a document or file on the blockchain

Notarise data onto the blockchain. Hashes any given file and submits to the network using any address
given.

Advanced: you can use a custom defined node to broadcast the notarisation. Use the (-g) grpc endpoint.
`

Notarise.args = [
   {
     name: 'notarialData',
     description: 'Data (file) to notarise',
     required: true,
   },
 ]

Notarise.flags = {

  testnet: flags.boolean({
    char: 't',
    default: false,
    description: 'uses testnet for the notarisation'
  }),

  mainnet: flags.boolean({
    char: 'm',
    default: false,
    description: 'uses mainnet for the notarisation'
  }),

  grpc: flags.string({
    char: 'g',
    required: false,
    description: 'advanced: grpc endpoint (for devnet/custom QRL network deployments)',
  }),

  message: flags.string({
    char: 'M',
    default: false,
    description: 'Additional (M)essage data to send (max 45 char)'
  }),

  wallet: flags.string({
    char: 'w',
    required: false,
    description: 'JSON (w)allet file notarisation will be sent from',
  }),

 password: flags.string({
    char: 'p',
    required: false,
    description: 'Encrypted QRL wallet file (p)assword'
  }),

  hexseed: flags.string({
    char: 'h',
    required: false,
    description: 'Secret (h)exseed/mnemonic of address notarisation should be sent from',
  }),

  fee: flags.string({
    char: 'f',
    required: false,
    description: 'QRL (f)ee for transaction in Shor (defaults to 0 Shor)'
  }),

  otsindex: flags.string({ 
    char: 'i',
    required: false,
    description: 'Unused OTS key (i)ndex for message transaction' 
  }),
}

module.exports = { Notarise }
