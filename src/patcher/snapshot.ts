import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { VPatchError } from '../errors.js';
import { stamp } from '../util.js';

/** The two files that fully describe the dependency state. node_modules is rebuilt from them. */
export interface Checkpoint {
  packageJson: string;
  lockfile: string;
}

export class SnapshotStore {
  constructor(
    private projectDir: string,
    private dirName: string,
    private lockfileName: string,
  ) {}

  private get root() {
    return path.join(this.projectDir, this.dirName, 'snapshots');
  }

  /** Read the live files into memory. */
  async read(): Promise<Checkpoint> {
    return {
      packageJson: await readFile(path.join(this.projectDir, 'package.json'), 'utf8'),
      lockfile: await readFile(path.join(this.projectDir, this.lockfileName), 'utf8'),
    };
  }

  /** Overwrite the live files from memory. */
  async write(cp: Checkpoint): Promise<void> {
    await writeFile(path.join(this.projectDir, 'package.json'), cp.packageJson);
    await writeFile(path.join(this.projectDir, this.lockfileName), cp.lockfile);
  }

  /** Persist a checkpoint to disk so `vpatch rollback` still works after a crash. */
  async persist(cp: Checkpoint, id = stamp()): Promise<string> {
    const dir = path.join(this.root, id);
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(dir, 'package.json'), cp.packageJson);
    await writeFile(path.join(dir, this.lockfileName), cp.lockfile);
    return id;
  }

  async load(id: string): Promise<Checkpoint> {
    if (!/^[\w.-]+$/.test(id)) throw new VPatchError('NO_SNAPSHOT', `Invalid snapshot id: ${id}`);
    const dir = path.join(this.root, id);
    try {
      return {
        packageJson: await readFile(path.join(dir, 'package.json'), 'utf8'),
        lockfile: await readFile(path.join(dir, this.lockfileName), 'utf8'),
      };
    } catch (err) {
      throw new VPatchError('NO_SNAPSHOT', `Snapshot "${id}" not found in ${this.root}`, { cause: err });
    }
  }

  async list(): Promise<string[]> {
    try {
      return (await readdir(this.root)).sort();
    } catch {
      return [];
    }
  }

  async latestId(): Promise<string> {
    const ids = await this.list();
    const last = ids[ids.length - 1];
    if (!last) throw new VPatchError('NO_SNAPSHOT', `No snapshots found in ${this.root}`);
    return last;
  }
}
