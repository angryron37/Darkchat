/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.createTable('users', function(table) {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.string('username', 50).unique().notNullable();
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.timestamp('last_seen');
    table.string('status', 20).defaultTo('offline');

    // Indexes for performance
    table.index('username');
    table.index('last_seen');
    table.index('status');
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTable('users');
};