import { expect, it } from "vitest";
import Ajv from "ajv";
import schema from "../../../schema/dataset.schema.json";
import { fixtureDataset } from "./fixture";

it("the engine's fixture dataset satisfies the shared dataset schema", () => {
  const validate = new Ajv({ allErrors: true }).compile(schema);
  expect(validate(fixtureDataset()), JSON.stringify(validate.errors)).toBe(true);
});
