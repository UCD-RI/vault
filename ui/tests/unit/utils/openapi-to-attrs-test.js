import { expandOpenApiProps, combineAttributes, combineFieldGroups } from 'vault/utils/openapi-to-attrs';
import { module, test } from 'qunit';
import DS from 'ember-data';
const { attr } = DS;

module('Unit | Util | OpenAPI Data Utilities', function() {
  const OPENAPI_RESPONSE_PROPS = {
    ttl: {
      type: 'string',
      format: 'seconds',
      'x-vault-displayName': 'TTL',
    },
    'awesome-people': {
      type: 'array',
      items: {
        type: 'string',
      },
      'x-vault-displayValue': 'Grace Hopper,Lady Ada',
    },
  };
  const EXPANDED_PROPS = {
    ttl: {
      editType: 'ttl',
      type: 'string',
      label: 'TTL',
    },
    awesomePeople: {
      editType: 'stringArray',
      type: 'array',
      defaultValue: 'Grace Hopper,Lady Ada',
    },
  };

  const EXISTING_MODEL_ATTRS = [
    {
      key: 'name',
      value: {
        isAttribute: true,
        name: 'name',
        options: {
          editType: 'string',
          label: 'Role name',
        },
      },
    },
    {
      key: 'awesomePeople',
      value: {
        isAttribute: true,
        name: 'awesomePeople',
        options: {
          label: 'People Who Are Awesome',
        },
      },
    },
  ];

  const COMBINED_ATTRS = {
    name: attr('string', {
      editType: 'string',
      type: 'string',
      label: 'Role name',
    }),
    ttl: attr('string', {
      editType: 'ttl',
      type: 'string',
      label: 'TTL',
    }),
    awesomePeople: attr({
      label: 'People Who Are Awesome',
      editType: 'stringArray',
      type: 'array',
      defaultValue: 'Grace Hopper,Lady Ada',
    }),
  };

  const NEW_FIELDS = ['one', 'two', 'three'];

  test('it creates objects from OpenAPI schema props', function(assert) {
    const generatedProps = expandOpenApiProps(OPENAPI_RESPONSE_PROPS);
    for (let propName in EXPANDED_PROPS) {
      assert.deepEqual(EXPANDED_PROPS[propName], generatedProps[propName], `correctly expands ${propName}`);
    }
  });

  test('it combines OpenAPI props with existing model attrs', function(assert) {
    const combined = combineAttributes(EXISTING_MODEL_ATTRS, EXPANDED_PROPS);
    for (let propName in EXISTING_MODEL_ATTRS) {
      assert.deepEqual(COMBINED_ATTRS[propName], combined[propName]);
    }
  });

  test('it adds new fields from OpenAPI to fieldGroups except for exclusions', function(assert) {
    let modelFieldGroups = [
      { default: ['name', 'awesomePeople'] },
      {
        Options: ['ttl'],
      },
    ];
    const excludedFields = ['two'];
    const expectedGroups = [
      { default: ['name', 'awesomePeople', 'one', 'three'] },
      {
        Options: ['ttl'],
      },
    ];
    const newFieldGroups = combineFieldGroups(modelFieldGroups, NEW_FIELDS, excludedFields);
    for (let groupName in modelFieldGroups) {
      assert.deepEqual(
        newFieldGroups[groupName],
        expectedGroups[groupName],
        'it incorporates all new fields except for those excluded'
      );
    }
  });
  test('it adds all new fields from OpenAPI to fieldGroups when excludedFields is empty', function(assert) {
    let modelFieldGroups = [
      { default: ['name', 'awesomePeople'] },
      {
        Options: ['ttl'],
      },
    ];
    const excludedFields = [];
    const expectedGroups = [
      { default: ['name', 'awesomePeople', 'one', 'two', 'three'] },
      {
        Options: ['ttl'],
      },
    ];
    const nonExcludedFieldGroups = combineFieldGroups(modelFieldGroups, NEW_FIELDS, excludedFields);
    for (let groupName in modelFieldGroups) {
      assert.deepEqual(
        nonExcludedFieldGroups[groupName],
        expectedGroups[groupName],
        'it incorporates all new fields'
      );
    }
  });
  test('it keeps fields the same when there are no brand new fields from OpenAPI', function(assert) {
    let modelFieldGroups = [
      { default: ['name', 'awesomePeople', 'two', 'one', 'three'] },
      {
        Options: ['ttl'],
      },
    ];
    const excludedFields = [];
    const expectedGroups = [
      { default: ['name', 'awesomePeople', 'two', 'one', 'three'] },
      {
        Options: ['ttl'],
      },
    ];
    const fieldGroups = combineFieldGroups(modelFieldGroups, NEW_FIELDS, excludedFields);
    for (let groupName in modelFieldGroups) {
      assert.deepEqual(fieldGroups[groupName], expectedGroups[groupName], 'it incorporates all new fields');
    }
  });
});
