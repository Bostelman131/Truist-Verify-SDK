import type { Config } from 'jest';

const config: Config = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    testMatch: ['**/test/**/*.test.ts'],
    moduleFileExtensions: ['ts', 'js'],
    transform: {
        '^.+\\.ts$': ['ts-jest', {
            tsconfig: {
                strict: true,
                esModuleInterop: true,
                module: 'CommonJS',
                target: 'ES2022',
                moduleResolution: 'Node',
                types: ['node', 'jest']
            }
        }]
    },
    collectCoverageFrom: ['src/**/*.ts'],
    coverageDirectory: 'coverage',
    coverageReporters: ['text', 'lcov']
};

export default config;
