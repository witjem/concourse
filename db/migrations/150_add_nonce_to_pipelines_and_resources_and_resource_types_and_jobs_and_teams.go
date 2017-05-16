package migrations

import "github.com/concourse/atc/dbng/migration"

func AddNonceToPipelinesAndResourcesAndResourceTypesAndJobsAndTeams(tx migration.LimitedTx) error {
	// _, err := tx.Exec(`
	// 	ALTER TABLE pipelines
	// 	ADD COLUMN nonce text;
	// `)
	// if err != nil {
	// 	return err
	// }

	_, err := tx.Exec(`
		ALTER TABLE teams
		ADD COLUMN nonce text;
`)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		ALTER TABLE teams
		ALTER COLUMN auth TYPE text;
`)
	if err != nil {
		return err
	}

	return nil
}
