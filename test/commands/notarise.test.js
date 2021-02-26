const assert = require('assert')
const {spawn} = require('child_process')

const processFlags = {
  detached: true,
  stdio: 'inherit',
}


describe('notarise #1', () => {
  const args = [
    'notarise',
  ]
  let exitCode
  before(done => {
    const process = spawn('./bin/run', args, processFlags)
    process.on('exit', code => {
      exitCode = code
      done()
    })
  })
  it('exit code should be non-0 if no file or wallet keys given', () => {
    assert.notStrictEqual(exitCode, 0)
  })
})


describe('notarise #1a', () => {
  const args = [
    'notarise',
    '/tmp/notAFile.txt',
  ]
  let exitCode
  before(done => {
    const process = spawn('./bin/run', args, processFlags)
    process.on('exit', code => {
      exitCode = code
      done()
    })
  })
  it('exit code should be non-0 if bad file given', () => {
    assert.notStrictEqual(exitCode, 0)
  })
})

describe('notarise #1b', () => {
  const args = [
    'notarise',
    '/etc/hosts',
  ]
  let exitCode
  before(done => {
    const process = spawn('./bin/run', args, processFlags)
    process.on('exit', code => {
      exitCode = code
      done()
    })
  })
  it('exit code should be non-0 if no wallet keys given', () => {
    assert.notStrictEqual(exitCode, 0)
  })
})

describe('notarise #1c', () => {
  const args = [
    'notarise',
    '/etc/hosts',
    '-h',
    '00003a2ebbbbe4adfca4b236a0bf91604438e5b09a35d660c7b77343ca8f1e983e115c5166aab75d4dcab819148b5e065aea',
  ]
  let exitCode
  before(done => {
    const process = spawn('./bin/run', args, processFlags)
    process.on('exit', code => {
      exitCode = code
      done()
    })
  })
  it('exit code should be non-0 if bad hexseed given', () => {
    assert.notStrictEqual(exitCode, 0)
  })
})


describe('notarise #1d', () => {
  const args = [
    'notarise',
    '/etc/hosts',
    '-h',
    '0004003a2ebbbbe4adfca4b236a0bf91604438e5b09a35d660c7b77343ca8f1e983e115c5166aab75d4dcab819148b5e065aea',
  ]
  let exitCode
  before(done => {
    const process = spawn('./bin/run', args, processFlags)
    process.on('exit', code => {
      exitCode = code
      done()
    })
  })
  it('exit code should be non-0 if no OTS given', () => {
    assert.notStrictEqual(exitCode, 0)
  })
})

describe('notarise #1e', () => {
  const args = [
    'notarise',
    '/etc/hosts',
    '-h',
    '0004003a2ebbbbe4adfca4b236a0bf91604438e5b09a35d660c7b77343ca8f1e983e115c5166aab75d4dcab819148b5e065aea',
    '-i',
    '1',
    '-M',
    'OVER45CHARwillfailAsItWillTIpTheByteCountOverTheEdgeAnywayWhoWouldWantToWriteAllTHis',
    '-t'
  ]
  let exitCode
  before(done => {
    const process = spawn('./bin/run', args, processFlags)
    process.on('exit', code => {
      exitCode = code
      done()
    })
  })
  it('exit code should be non-0 if too long message string added', () => {
    assert.notStrictEqual(exitCode, 0)
  })
})



describe('notarise #2', () => {
  const args = [
    'notarise',
    '/etc/hosts',
    '-h',
    '0004003a2ebbbbe4adfca4b236a0bf91604438e5b09a35d660c7b77343ca8f1e983e115c5166aab75d4dcab819148b5e065aea',
    '-i',
    '1',
    '-t'
  ]
  let exitCode
  before(done => {
    const process = spawn('./bin/run', args, processFlags)
    process.on('exit', code => {
      exitCode = code
      done()
    })
  })
  it('exit code should be 0 if notarisation succeeded', () => {
    assert.strictEqual(exitCode, 0)
  })
})

describe('notarise #2a', () => {
  const args = [
    'notarise',
    '/etc/hosts',
    '-h',
    '0004003a2ebbbbe4adfca4b236a0bf91604438e5b09a35d660c7b77343ca8f1e983e115c5166aab75d4dcab819148b5e065aea',
    '-i',
    '1',
    '-M',
    'TestTestTest',
    '-t'
  ]
  let exitCode
  before(done => {
    const process = spawn('./bin/run', args, processFlags)
    process.on('exit', code => {
      exitCode = code
      done()
    })
  })
  it('exit code should be 0 if notarisation succeeded with message data added', () => {
    assert.strictEqual(exitCode, 0)
  })
})