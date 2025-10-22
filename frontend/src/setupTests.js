// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom';

// Mock TextEncoder/TextDecoder
class MockTextEncoder {
  encode(str) {
    return Buffer.from(str, 'utf-8');
  }
}

class MockTextDecoder {
  decode(buffer) {
    return Buffer.from(buffer).toString('utf-8');
  }
}

// Mock Web APIs not available in Node.js
class MockBroadcastChannel {
  postMessage() {}
  addEventListener() {}
  removeEventListener() {}
  close() {}
}

class MockTransformStream {
  constructor() {
    this.writable = {
      write() {},
      close() {}
    };
    this.readable = {
      read() {},
      cancel() {}
    };
  }
}

global.TextEncoder = MockTextEncoder;
global.TextDecoder = MockTextDecoder;
global.BroadcastChannel = MockBroadcastChannel;
global.TransformStream = MockTransformStream;
