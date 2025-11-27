/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.createTable('messages_metadata', function(table) {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.uuid('sender_id').references('id').inTable('users').onDelete('CASCADE');
    table.uuid('receiver_id').references('id').inTable('users').onDelete('CASCADE');
    table.string('message_id', 255).unique().notNullable(); // Redis key reference
    table.text('encrypted_aes_key').notNullable();
    table.timestamp('expires_at').notNullable();
    table.boolean('one_time_view').defaultTo(false);
    table.timestamp('created_at').defaultTo(knex.fn.now());
    table.string('status', 20).defaultTo('delivered');
    table.boolean('anonymous').defaultTo(false);

    // Indexes for performance
    table.index('sender_id');
    table.index('receiver_id');
    table.index('message_id');
    table.index('expires_at');
    table.index('status');
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTable('messages_metadata');
};