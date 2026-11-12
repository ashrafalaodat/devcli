import assert from 'node:assert/strict';
import {test} from 'node:test';
import {formatLabels, parseLabels} from './labels.ts';

test('label input normalizes whitespace and ignores blank comma-separated entries', () => {
  assert.deepEqual(parseLabels(' , region = eu, environment = testing, , '), {region: 'eu', environment: 'testing'});
  assert.deepEqual(parseLabels(' , , '), {});
});

test('empty values require explicit PAT-selector mode and remain distinguishable from absent labels', () => {
  assert.throws(() => parseLabels('purpose='), /key=value/);
  assert.throws(() => parseLabels('purpose=  '), /key=value/);
  const selector = parseLabels('purpose=,region=eu', true);
  assert.equal(Object.hasOwn(selector, 'purpose'), true);
  assert.equal(selector.purpose, '');
  assert.equal(Object.hasOwn(selector, 'absent'), false);
  assert.equal(formatLabels(selector), 'purpose=,region=eu');
  assert.deepEqual(parseLabels(formatLabels(selector), true), selector);
});

test('duplicate keys and incomplete fields are rejected before sending a request', () => {
  for (const input of ['region', '=eu', 'region=eu,region=us', 'region=eu, region = eu']) {
    assert.throws(() => parseLabels(input), /Label/);
  }
  assert.throws(() => parseLabels(' = value', true), /Label/);
  assert.throws(() => parseLabels('empty=,empty=', true), /duplicate/);
});

test('label keys that resemble prototype properties remain own data properties', () => {
  const labels = parseLabels('__proto__=safe,constructor=also-safe,hasOwnProperty=own');
  assert.equal(Object.getPrototypeOf(labels), Object.prototype);
  assert.equal(Object.hasOwn(labels, '__proto__'), true);
  assert.equal(labels.__proto__, 'safe');
  assert.equal(Object.hasOwn(labels, 'constructor'), true);
  assert.equal(labels.constructor, 'also-safe');
  assert.equal(Object.hasOwn(labels, 'hasOwnProperty'), true);
  assert.equal(labels.hasOwnProperty, 'own');
  assert.equal(Object.getPrototypeOf({}), Object.prototype);
  assert.throws(() => parseLabels('__proto__=one,__proto__=two'), /duplicate/);
});

test('formatting is stable and retains the complete text after the first equals sign', () => {
  assert.equal(formatLabels({region: 'eu', environment: 'testing'}), 'environment=testing,region=eu');
  const labels = parseLabels('reference=one=two,region=eu');
  assert.equal(labels.reference, 'one=two');
  assert.equal(formatLabels(labels), 'reference=one=two,region=eu');
  assert.equal(formatLabels({}), '');
});
