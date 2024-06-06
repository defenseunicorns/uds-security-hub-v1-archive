package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestRegisterCounter tests the RegisterCounter method of the Collector.
func TestRegisterCounter(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	counter, err := collector.RegisterCounter(ctx, "test_counter", "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.AddCounter(ctx, "test_counter", 1, "label1")
	if err != nil {
		t.Fatal(err)
	}

	// Validate the counter
	counterVec, ok := counter.(prometheus.Collector)
	if !ok {
		t.Fatal("counter is not a Collector")
	}
	err = testutil.CollectAndCompare(counterVec, strings.NewReader(`
	    # HELP uds_security_hub_uds_security_hub_test_counter Counter for uds_security_hub_test_counter
		# TYPE uds_security_hub_uds_security_hub_test_counter counter
		uds_security_hub_uds_security_hub_test_counter{label1="label1"} 1
	`))
	if err != nil {
		t.Fatal(err)
	}
}

// TestRegisterHistogram tests the RegisterHistogram method of the Collector.
func TestRegisterHistogram(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	_, err := collector.RegisterHistogram(ctx, "test_histogram", "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.ObserveHistogram(ctx, "test_histogram", 2.5, "label1")
	if err != nil {
		t.Fatal(err)
	}
}

// TestRegisterGauge tests the RegisterGauge method of the Collector.
func TestRegisterGauge(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	gaugeVec, err := collector.RegisterGauge(ctx, "test_gauge", "label1")
	if err != nil {
		t.Fatal(err)
	}

	a, ok := gaugeVec.(prometheus.Collector)
	if !ok {
		t.Fatal("gaugeVec is not a Collector")
	}
	gaugeVec.Add(1)
	err = testutil.CollectAndCompare(a, strings.NewReader(`
	    # HELP uds_security_hub_uds_security_hub_test_gauge Gauge for uds_security_hub_test_gauge
			# TYPE uds_security_hub_uds_security_hub_test_gauge gauge
		uds_security_hub_uds_security_hub_test_gauge{label1="label1"} 1
	`))
	if err != nil {
		t.Fatal(err)
	}
}

// TestMetricsHandler tests the MetricsHandler method of the Collector.
func TestMetricsHandler(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	handler := collector.MetricsHandler()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

// TestNonExistingCounter tests the AddCounter method of the Collector.
func TestNonExistingCounter(t *testing.T) {
	ctx := WithMetrics(context.Background(), "uds_security_hub")
	collector := FromContext(ctx, "uds_security_hub")

	err := collector.AddCounter(ctx, "non_existing_counter", 1, "label1")
	if err == nil {
		t.Fatal("expected error for non-existing counter")
	}
}

func Test_prometheusCollector_MeasureFunctionExecutionTime(t *testing.T) {
	type fields struct {
		histograms map[string]*prometheus.HistogramVec
		gauges     map[string]*prometheus.GaugeVec
		counters   map[string]*prometheus.CounterVec
		registry   *prometheus.Registerer
		name       string
	}
	type args struct {
		in0  context.Context
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &prometheusCollector{
				histograms: tt.fields.histograms,
				gauges:     tt.fields.gauges,
				counters:   tt.fields.counters,
				registry:   tt.fields.registry,
				name:       tt.fields.name,
			}
			got, err := p.MeasureFunctionExecutionTime(tt.args.in0, tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("MeasureFunctionExecutionTime() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Since got is a function, we cannot use reflect.DeepEqual to compare it.
			// Instead, we can check if got is not nil.
			if got == nil {
				t.Errorf("MeasureFunctionExecutionTime() got = nil, want non-nil function")
			}
		})
	}
}

func Test_prometheusCollector_UnregisterCounter(t *testing.T) {
	type fields struct { //nolint:govet
		name       string
		registry   *prometheus.Registerer
		histograms map[string]*prometheus.HistogramVec
		gauges     map[string]*prometheus.GaugeVec
		counters   map[string]*prometheus.CounterVec
	}
	type args struct {
		in0  context.Context
		name string
		in2  []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Success - Unregister existing counter",
			fields: fields{
				counters: map[string]*prometheus.CounterVec{
					"uds_security_hub_test_counter": prometheus.NewCounterVec(prometheus.CounterOpts{
						Name: "uds_security_hub_test_counter",
						Help: "Test counter",
					}, []string{"label1"}),
				},
				name: "uds_security_hub",
			},
			args: args{
				in0:  context.Background(),
				name: "test_counter",
				in2:  []string{"label1"},
			},
			wantErr: false,
		},
		{
			name: "Success - Unregister non-existent counter",
			fields: fields{
				counters: map[string]*prometheus.CounterVec{},
				name:     "uds_security_hub",
			},
			args: args{
				in0:  context.Background(),
				name: "non_existent_counter",
				in2:  []string{"label1"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &prometheusCollector{
				histograms: tt.fields.histograms,
				gauges:     tt.fields.gauges,
				counters:   tt.fields.counters,
				registry:   tt.fields.registry,
				name:       tt.fields.name,
			}
			if err := p.UnregisterCounter(tt.args.in0, tt.args.name, tt.args.in2...); (err != nil) != tt.wantErr {
				t.Errorf("UnregisterCounter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_prometheusCollector_UnregisterGauge(t *testing.T) {
	type fields struct { //nolint:govet
		name       string
		registry   *prometheus.Registerer
		histograms map[string]*prometheus.HistogramVec
		gauges     map[string]*prometheus.GaugeVec
		counters   map[string]*prometheus.CounterVec
	}
	type args struct {
		in0  context.Context
		name string
		in2  []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Success - Unregister existing gauge",
			fields: fields{
				gauges: map[string]*prometheus.GaugeVec{
					"uds_security_hub_test_gauge": prometheus.NewGaugeVec(prometheus.GaugeOpts{
						Name: "uds_security_hub_test_gauge",
						Help: "Test gauge",
					}, []string{"label1"}),
				},
				name: "uds_security_hub",
			},
			args: args{
				in0:  context.Background(),
				name: "test_gauge",
				in2:  []string{"label1"},
			},
			wantErr: false,
		},
		{
			name: "Success - Unregister non-existent gauge",
			fields: fields{
				gauges: map[string]*prometheus.GaugeVec{},
				name:   "uds_security_hub",
			},
			args: args{
				in0:  context.Background(),
				name: "non_existent_gauge",
				in2:  []string{"label1"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &prometheusCollector{
				histograms: tt.fields.histograms,
				gauges:     tt.fields.gauges,
				counters:   tt.fields.counters,
				registry:   tt.fields.registry,
				name:       tt.fields.name,
			}
			if err := p.UnregisterGauge(tt.args.in0, tt.args.name, tt.args.in2...); (err != nil) != tt.wantErr {
				t.Errorf("UnregisterGauge() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_prometheusCollector_UnregisterHistogram(t *testing.T) {
	type fields struct { //nolint:govet
		name       string
		registry   *prometheus.Registerer
		histograms map[string]*prometheus.HistogramVec
		gauges     map[string]*prometheus.GaugeVec
		counters   map[string]*prometheus.CounterVec
	}
	type args struct {
		in0  context.Context
		name string
		in2  []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Success - Unregister existing histogram",
			fields: fields{
				histograms: map[string]*prometheus.HistogramVec{
					"uds_security_hub_test_histogram": prometheus.NewHistogramVec(prometheus.HistogramOpts{
						Name: "uds_security_hub_test_histogram",
						Help: "Test histogram",
					}, []string{"label1"}),
				},
				name: "uds_security_hub",
			},
			args: args{
				in0:  context.Background(),
				name: "test_histogram",
				in2:  []string{"label1"},
			},
			wantErr: false,
		},
		{
			name: "Success - Unregister non-existent histogram",
			fields: fields{
				histograms: map[string]*prometheus.HistogramVec{},
				name:       "uds_security_hub",
			},
			args: args{
				in0:  context.Background(),
				name: "non_existent_histogram",
				in2:  []string{"label1"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &prometheusCollector{
				histograms: tt.fields.histograms,
				gauges:     tt.fields.gauges,
				counters:   tt.fields.counters,
				registry:   tt.fields.registry,
				name:       tt.fields.name,
			}
			if err := p.UnregisterHistogram(tt.args.in0, tt.args.name, tt.args.in2...); (err != nil) != tt.wantErr {
				t.Errorf("UnregisterHistogram() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_prometheusCollector_AddHistogram(t *testing.T) {
	type fields struct { //nolint:govet
		name       string
		registry   *prometheus.Registerer
		histograms map[string]*prometheus.HistogramVec
		gauges     map[string]*prometheus.GaugeVec
		counters   map[string]*prometheus.CounterVec
	}
	type args struct { //nolint:govet
		in0    context.Context
		name   string
		value  float64
		labels []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Success - Add value to existing histogram",
			fields: fields{
				histograms: map[string]*prometheus.HistogramVec{
					"uds_security_hub_test_histogram": prometheus.NewHistogramVec(prometheus.HistogramOpts{
						Name: "uds_security_hub_test_histogram",
						Help: "Test histogram",
					}, []string{"label1"}),
				},
				name: "uds_security_hub",
			},
			args: args{
				in0:    context.Background(),
				name:   "test_histogram",
				value:  2.5,
				labels: []string{"label1"},
			},
			wantErr: false,
		},
		{
			name: "Error - Add value to non-existent histogram",
			fields: fields{
				histograms: map[string]*prometheus.HistogramVec{},
				name:       "uds_security_hub",
			},
			args: args{
				in0:    context.Background(),
				name:   "non_existent_histogram",
				value:  2.5,
				labels: []string{"label1"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &prometheusCollector{
				histograms: tt.fields.histograms,
				gauges:     tt.fields.gauges,
				counters:   tt.fields.counters,
				registry:   tt.fields.registry,
				name:       tt.fields.name,
			}
			if err := p.AddHistogram(tt.args.in0, tt.args.name, tt.args.value, tt.args.labels...); (err != nil) != tt.wantErr {
				t.Errorf("AddHistogram() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_prometheusCollector_SetGauge(t *testing.T) {
	type fields struct { //nolint:govet
		name       string
		registry   *prometheus.Registerer
		histograms map[string]*prometheus.HistogramVec
		gauges     map[string]*prometheus.GaugeVec
		counters   map[string]*prometheus.CounterVec
	}
	type args struct { //nolint:govet
		in0    context.Context
		name   string
		value  float64
		labels []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Success - Set value of existing gauge",
			fields: fields{
				gauges: map[string]*prometheus.GaugeVec{
					"uds_security_hub_test_gauge": prometheus.NewGaugeVec(prometheus.GaugeOpts{
						Name: "uds_security_hub_test_gauge",
						Help: "Test gauge",
					}, []string{"label1"}),
				},
				name: "uds_security_hub",
			},
			args: args{
				in0:    context.Background(),
				name:   "test_gauge",
				value:  2.5,
				labels: []string{"label1"},
			},
			wantErr: false,
		},
		{
			name: "Error - Set value of non-existent gauge",
			fields: fields{
				gauges: map[string]*prometheus.GaugeVec{},
				name:   "uds_security_hub",
			},
			args: args{
				in0:    context.Background(),
				name:   "non_existent_gauge",
				value:  2.5,
				labels: []string{"label1"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &prometheusCollector{
				histograms: tt.fields.histograms,
				gauges:     tt.fields.gauges,
				counters:   tt.fields.counters,
				registry:   tt.fields.registry,
				name:       tt.fields.name,
			}
			if err := p.SetGauge(tt.args.in0, tt.args.name, tt.args.value, tt.args.labels...); (err != nil) != tt.wantErr {
				t.Errorf("SetGauge() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
